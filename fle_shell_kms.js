// Simple demonstration using MongoDB Client-Side Field Level Encryption (KMS version)
// Requires Community or (preferrably) Enterprise Shell and a MongoDB 4.2+ database
// Local, stand-alone, or Atlas MongoDB will all work.

// To use this, just open Mongo shell, with this file, e.g.: `mongo localhost fle_shell_quickstart_part2.js`
// Note, you will need the attached `kms_config.env` file, see below.
// See: Client-Side Field Level Encryption Quickstart Part 1:
//  https://gist.github.com/kennwhite/e64e5b6770e89a797c3a08ecaa0cb7d0

var demoDB = "demoFLE"
var keyVaultColl = "__keystore"  // nothing special about this key vault collection name, but make it stand out

const ENC_DETERM = 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
const ENC_RANDOM = 'AEAD_AES_256_CBC_HMAC_SHA_512-Random'

// populate AWS & connection string variables
var env = {}

print("\nLoading connection & key settings file...")
try {
   load( 'kms_config.env' );
} catch (err) {
   print("Exiting: Unable to open file: " + envFile );
   quit()
}
if (env.KMSKEY == "xxxxxxxxxxxxxxxxxxxxxxxxx"){
   print("\nPlease generate a KMS key & IAM credentials (see `kms_config.env` file). Exiting. \n\n"); quit();
} 

// javascript shell script equivalent of: use demoFLE
db = db.getSiblingDB( demoDB )

// Wipe sandbox. Approximate Atlas equivalent of: db.dropDatabase()
db.getCollectionNames().forEach(function(c){db.getCollection(c).drop()});


var clientSideFLEOptions = {
   "kmsProviders" : {
      "aws" : {
          "accessKeyId" : env.KMSKID ,
          "secretAccessKey" : env.KMSKEY
         }
      },
    schemaMap: {},  // on first invocation prior to field key generation, this should be empty
    keyVaultNamespace: demoDB + "." + keyVaultColl
};

encryptedSession = new Mongo(env.connStr, clientSideFLEOptions);

var keyVault = encryptedSession.getKeyVault();

print("Attempting to create 2 field keys aliased fieldKey1 and fieldKey2...")
keyVault.createKey("aws", env.KMSARN, ["fieldKey1"])
keyVault.createKey("aws", env.KMSARN, ["fieldKey2"])

keyVault
db.getCollection( keyVaultColl ).find().pretty()

print("Attempting to retrieve field keys...")
var key1 = db.getCollection( keyVaultColl ).find({ keyAltNames: 'fieldKey1' }).toArray()[0]._id
var key2 = db.getCollection( keyVaultColl ).find({ keyAltNames: 'fieldKey2' }).toArray()[0]._id

print("Setting server-side json schema validation to enforce that ssn and dob are of type binData (output of fle) on `people` collection...")
db.createCollection("people")
db.runCommand({
   collMod: "people",
   validator: {
      $jsonSchema: {
         "bsonType": "object",
         "properties": {
            "ssn": { bsonType: "binData" },
            "dob": { bsonType: "binData" },
         }
      }
   }
})

print("Creating client-side json schema config for automatic encryption on `people` collection...")
var peopleSchema = {
   "demoFLE.people": {
      "bsonType": "object",
      "properties": {
         "ssn": {
            "encrypt": {
               "bsonType": "string",
               "algorithm": ENC_DETERM,
               "keyId": [ key1 ]
            }
         },
         "dob": {
            "encrypt": {
               "bsonType": "date",
               "algorithm": ENC_RANDOM,
               "keyId": [ key1 ]
            }
         },
         "contact": {
            "bsonType": "object",
            "properties": {
               "email": {
                  "encrypt": {
                     "bsonType": "string",
                     "algorithm": ENC_DETERM,
                     "keyId": [ key2 ]
                  }
               },
               "mobile": {
                  "encrypt": {
                     "bsonType": "string",
                     "algorithm": ENC_DETERM,
                     "keyId": [ key2 ]
                  }
               }
            },
         },
      }
   }
}


print("Updating FLE mode session to enable server- and client-side json schema for automatic encryption...")

var clientSideFLEOptions = {
   "kmsProviders": {
      "aws": {
         "accessKeyId": env.KMSKID,
         "secretAccessKey": env.KMSKEY
      }
   },
   schemaMap: peopleSchema,
   keyVaultNamespace: demoDB + "." + keyVaultColl
}
var encryptedSession = new Mongo(env.connStr, clientSideFLEOptions)
var db = encryptedSession.getDB( demoDB );

print("Attempting to detect server-side Enterprise edition mode...")
var edition = db.runCommand({buildInfo:1}).modules
var enterprise = false
if ( edition !== undefined && edition.length != 0 ){
	var enterprise = true
}
print("MongoDB server running in enterprise mode: " + enterprise + "\n")

print("Attempting to insert sample document with automatic encryption...")
try {
 var res = null
 res = db.people.insert({
   firstName: 'Grace',
   lastName:  'Hopper',
   ssn: "901-01-0001",
   dob: new Date('1989-12-13'),
   address: {
      street: '123 Main Street',
      city:   'Omaha',
      state:  'Nebraska',
      zip:    '90210'
   },
   contact: {
      mobile: '202-555-1212',
      email:  'grace@example.com',
   }
  })
} catch (err) {
   res = err
}
print("Result: " + res)

print("Attempting to insert sample document with explicit encryption...")
try{
  var res = null
  res = db.people.insert({
   firstName: 'Alan',
   lastName:  'Turing',
   ssn: db.getMongo().encrypt( key1 , "901-01-0002" , ENC_DETERM ),
   dob: db.getMongo().encrypt( key1 , new Date('1912-06-23'), ENC_RANDOM ),
   address: {
      street: '123 Oak Lane',
      city:   'Cleveland',
      state:  'Ohio',
      zip:    '90210'
   },
   contact: {
      mobile: db.getMongo().encrypt( key2 , '202-555-1234', ENC_DETERM ),
      email:  db.getMongo().encrypt( key2 , 'alan@example.net', ENC_DETERM ),
   }
 })
} catch (err) {
	res = err
}
print("Result: " + res)

print("\nEnabling session bypass on automatic encrypt/decrypt... \n")

var clientSideFLEOptions = {
   "kmsProviders": {
      "aws": {
         "accessKeyId": env.KMSKID,
         "secretAccessKey": env.KMSKEY
      }
   },
   bypassAutoEncryption: true,
   schemaMap: peopleSchema,
   keyVaultNamespace: demoDB + "." + keyVaultColl
}
var encryptedSession = new Mongo(env.connStr, clientSideFLEOptions)
var db = encryptedSession.getDB( demoDB );

print("Attempting to insert sample document with explicit encryption...")

try{
  var res = null
  res = db.people.insert({
   firstName: 'Alan',
   lastName:  'Turing',
   ssn: db.getMongo().encrypt( key1 , "901-01-0002" , ENC_DETERM ),
   dob: db.getMongo().encrypt( key1 , new Date('1912-06-23'), ENC_RANDOM ),
   address: {
      street: '123 Oak Lane',
      city:   'Cleveland',
      state:  'Ohio',
      zip:    '90210'
   },
   contact: {
      mobile: db.getMongo().encrypt( key2 , '202-555-1234', ENC_DETERM ),
      email:  db.getMongo().encrypt( key2 , 'alan@example.net', ENC_DETERM ),
   }
 })
} catch (err) {
	res = err
}
print("Result: " + res)

print("Dumping (raw) records from `people`:")
var records = db.people.find().pretty()
while (records.hasNext()) {
   printjson(records.next());
}

print("\nDisabling session bypass for automatic encrypt/decrypt...\n")
var clientSideFLEOptions = {
   kmsProviders: {
      aws: {
         accessKeyId: env.KMSKID,
         secretAccessKey: env.KMSKEY
      }
   },
   schemaMap: peopleSchema,
   keyVaultNamespace: demoDB + "." + keyVaultColl
}
var encryptedSession = new Mongo(env.connStr, clientSideFLEOptions)
var db = encryptedSession.getDB( demoDB );

print("Dumping (automatic decrypted) records from `people`:")
var records = db.people.find().pretty()
while (records.hasNext()) {
   printjson(records.next());
}

print("\nCreating an index on the encrypted ssn field...")
db.people.createIndex({ssn:1})
print("Fetching a person record by ssn value against the encrypted field...")
records = db.people.find({ssn: "901-01-0002"}).pretty()
while (records.hasNext()) {
   printjson(records.next());
}

print("\nDemo complete.")
