
# rn-crypto-module

  This repo is a fork from  **[react-native-rsa-native](https://github.com/amitaymolko/react-native-rsa-native)**

A native implementation of RSA key generation and encryption/decryption, sign/verify.

A native implementation of EC key generation and encryption/decryption, sign/verify.

Keychain implementation

Implementation is in PKCS1

Csr generation

## Support

iOS 10+

android 4.1+ (API 16)

## Status

Features:

Generation,

Encryption,

Decryption,

Sign,

Verify,

Csr generation,

Keychain support

## Getting started

`$ yarn add rn-crypto-module`

or:

`$ npm install rn-crypto-module --save`

## Older React-Native versions

If you are using an older version of React Native and are having issues try using v1.1.14

## Example Usage

These basic examples show a typical use case using both promise chains

and async/await.

See [the full API documentation below](#documentation)

for more detail on the methods available.

### Encrypt a message

Encrypt a message and subsequently decrypt it,

using the RSA class in a promise chain structure.

```js

import { RSA } from  'rn-crypto-module';

let  message = "my secret message";

RSA.generateKeys(4096) // set key size
.then(keys  => {
  console.log('4096 private:', keys.private); // the private key
  console.log('4096 public:', keys.public); // the public key
  RSA.encrypt(message, keys.public)
.then(encodedMessage  => {
  console.log(`the encoded message is ${encodedMessage}`);
  RSA.decrypt(encodedMessage, keys.private)

.then(decryptedMessage  => {
  console.log(`The original message was ${decryptedMessage}`);
});

});

});

```

### Sign a message

Sign a message and subsequently verify it,

using the RSAKeychain class in an async/await structure.

```typescript

import { RSAKeychain } from  'rn-crypto-module';


async  main() {

let  keyTag = 'com.domain.mykey';

let  message = "message to be verified";


let  publicKey = await  generateKeyPair(keyTag);

// Share the generated public key with third parties as desired.

let  messageSignature = await  RSAKeychain.sign(message, keyTag);

if (await  RSAKeychain.verify(messageSignature, message, keyTag)) {
// The signature matches: trust this message.
} else {
// The signature does not match.
}

await  RSAKeychain.deletePrivateKey(keyTag);
}

async  generateKeyPair(keyTag : string) {

  let  keys = await  RSAKeychain.generate(keyTag);

  return  keys.public;

}

```

Check out example App.js for a full example

## Documentation

### RSA Class

A class that performs RSA cryptographic primitives

in a simple and straightforward manner.

If you would prefer to use the underlying operating system's built-in

security keychain, use [the RSAKeychain Class](#rsakeychain-class) instead.

#### generateKeys

`static generateKeys(keySize : number) : Promise<KeyPair>`

Generate a public/private key pair of the given key size.

#### generate

`static generate() : Promise<KeyPair>`

Equivalent to `generateKeys(2048)`

#### encrypt

`static encrypt(message : string, publicKey : string) : Promise<string>`

Encrypt a given message with the provided public key, so it is decryptable with the matching private key.

#### decrypt

`static decrypt(encodedMessage : string, privateKey : string) : Promise<string>`

Decrypt a given encrypted message using the private key.

#### sign

`static sign(message: string, privateKey : string) : Promise<string>`

Sign a given message with the private key, so that any user with the message, the returned signature, and the matching public key can verify it was signed under this key.

#### verify

`static verify(signature : string, message : string, publicKey : string) : Promise<boolean>`

Verify whether or not a provided signature was produced by signing the given message with the private key paired to the provided public key.

### RSAKeychain Class

Support: android 4.3+ (API 18)

Like [the RSA Class](#rsa-class),

but when its methods are called, instead of directly accessing the private key,

the private key is stored in the underlying operating system's keychain

(see documentation

[for iOS](https://developer.apple.com/documentation/security/keychain_services) and

[for Android](https://developer.android.com/reference/android/security/KeyChain))

using a tag which the app can use to access it.

Methods then take this tag instead of the private key.

#### generateKeys

`static generateKeys(keyTag : string, keySize : number) : Promise<PublicKey>`

Generate a public/private key pair of the given key size,

and store the private key in the operating system keychain.

#### generate

`static generate(keyTag : string) : Promise<KeyPair>`

Equivalent to `generateKeys(keyTag, 2048)`

#### encrypt

`static encrypt(message : string, keyTag : string) : Promise<string>`

Retrieve the public key associated with the key tag,

and encrypt a given message with that key,

so it is decryptable with the matching private key.

#### decrypt

`static decrypt(encodedMessage : string, keyTag : string) : Promise<string>`

Decrypt a given encrypted message using the private key

associated with the given key tag.

#### sign

`static sign(message: string, keyTag : string) : Promise<string>`

Sign a given message with the private key associated with the given key tag,

so that any user with

the message, the returned signature, and the matching public key

can verify it was signed under this key.

#### signWithAlgorithm

`static sign(message: string, keyTag : string, algorithm?: 'SHA256withRSA' | 'SHA512withRSA') : Promise<string>`

Sign a given message with the private key associated with the given key tag,

so that any user with

the message, the returned signature, and the matching public key

can verify it was signed under this key. The user can use **SHA256withRSA** or **SHA512withRSA** algorithm for signing.

**SHA256withRSA** algorithm is not backward compatible on android and the user needs to generate new keypair for this to work. (available from ^1.1.0). The default is **SHA512withRSA** and if one wishes to use **SHA512withRSA** for signing without new keypair, then use the above sign method.

#### verify

`static verify(signature : string, message : string, keyTag : string) : Promise<boolean>`

Verify whether or not a provided signature was produced by signing the given message with private key associated with the given key tag.

#### verifyWithAlgorithm

`static verify(signature : string, message : string, keyTag : string, algorithm?: 'SHA256withRSA' | 'SHA512withRSA') : Promise<boolean>`

Verify whether or not a provided signature was produced by signing the given message with private key associated with the given key tag.

#### deletePrivateKey

`static deletePrivateKey(keyTag : string) : Promise<boolean>`

Delete the private key from the operating system's keychain.

Returns true if the key was removed successfully.

#### generateCSR

`generateCSR(keyTag: string, attributes: object, signature?: TypeCrypto): Promise<CSRKey>`

Generate a csr

Atrributes is an object with this supported keys:

`commonName, organizationName, organizationUnitName, countryName, stateOrProvinceName, localityName, emailAddress, organizationIdentifier, title, description, givenName, surname`

Returns an object `{csr: csrPem}`

### KeyPair Type

Note: The `KeyPair` type does not strictly exist.

Documentation provided here for convenience of understanding the return types

of other methods.

Property | Description

--|--

`private : string` | The RSA private key.

`public : string` | The RSA public key.

### PublicKey Type

Note: The `PublicKey` type does not strictly exist.

Documentation provided here for convenience of understanding the return types

of other methods.

Property | Description

--|--

`public : string` | The RSA public key.

## Credit

* Originally based on <https://github.com/SamSaffron/react-native-key-pair>

* iOS implementation [reference](https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1)
