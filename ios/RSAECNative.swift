//
//  RSANative.swift
//  BVLinearGradient

import Foundation
import CommonCrypto

typealias SecKeyPerformBlock = (SecKey) -> ()


class RSAECNative: NSObject {
    var publicKey: SecKey?
    var privateKey: SecKey?
    var keyTag: String?
    let publicKeyTag: String?
    let privateKeyTag: String?
    var publicKeyBits: Data?
    var keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
    
    public init(keyTag: String?){
        self.publicKeyTag = "\(keyTag ?? "").public"
        self.privateKeyTag = "\(keyTag ?? "").private"
        self.keyTag = keyTag
        super.init()
    }
    
    public convenience override init(){
        self.init(keyTag: nil)
    }
    
    public func generate(keySize: Int) -> Bool? {
        var publicKeyParameters: [String: AnyObject] = [
            String(kSecAttrAccessible): kSecAttrAccessibleAlways,
        ]
        
        var privateKeyParameters: [String: AnyObject] = [
            String(kSecAttrAccessible): kSecAttrAccessibleAlways,
        ]
        
        if((self.keyTag) != nil){
            privateKeyParameters[String(kSecAttrIsPermanent)] = kCFBooleanTrue
            privateKeyParameters[String(kSecAttrApplicationTag)] = self.privateKeyTag as AnyObject
            
            publicKeyParameters[String(kSecAttrIsPermanent)] = kCFBooleanTrue
            publicKeyParameters[String(kSecAttrApplicationTag)] = self.publicKeyTag as AnyObject
            
        }
        
        #if !arch(i386) && !arch(x86_64)
        //This only works for Secure Enclave consistign of 256 bit key, note, the signatureType is irrelavent for this check
        if keyAlgorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type{
            let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                         kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                         .privateKeyUsage,
                                                         nil)!   // Ignore error
            
            privateKeyParameters[String(kSecAttrAccessControl)] = access
        }
        #endif
        
        //Define what type of keys to be generated here
        var parameters: [String: AnyObject] = [
            String(kSecReturnRef): kCFBooleanTrue,
            kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject,
        ]
        parameters[String(kSecAttrKeySizeInBits)] = keySize as AnyObject
        parameters[String(kSecAttrKeyType)] = keyAlgorithm.secKeyAttrType
        
        #if !arch(i386) && !arch(x86_64)
        
        //iOS only allows EC 256 keys to be secured in enclave. This will attempt to allow any EC key in the enclave, assuming iOS will do it outside of the enclave if it doesn't like the key size, note: the signatureType is irrelavent for this check
        if keyAlgorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type{
            parameters[String(kSecAttrTokenID)] = kSecAttrTokenIDSecureEnclave
        }
        
        #endif
        
        var error: Unmanaged<CFError>?
        self.privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
        
        if self.privateKey == nil {
            print("Error occured: keys weren't created")
            return nil
        }
        
        self.publicKey = SecKeyCopyPublicKey(self.privateKey!)
        
        guard self.publicKey != nil else {
            print( "Error  in setUp(). PublicKey shouldn't be nil")
            return nil
        }
        
        guard self.privateKey != nil else{
            print("Error  in setUp(). PrivateKey shouldn't be nil")
            return nil
        }
        return true
    }
    
    public func generateEC() -> Bool? {
        self.keyAlgorithm = KeyAlgorithm.ec(signatureType: .sha256)
        // ios support 256
        return self.generate(keySize: 256);
    }
    
    public func generateCSR(attributes: NSDictionary, withAlgorithm: String) -> String? {
        self.setAlgorithm(algorithm: withAlgorithm)
        self.publicKeyBits = self.getPublicKeyChainData(tag: self.publicKeyTag!)
        var csrString: String?
        let csrBlock: SecKeyPerformBlock = { privateKey in
            let csr = CertificateSigningRequest(
                attributes: attributes,
                keyAlgorithm:self.keyAlgorithm
            )
            csrString = csr.buildCSRAndReturnString(
                self.publicKeyBits!,
                privateKey: privateKey
            )
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!, block: csrBlock)
        } else {
            csrBlock(self.privateKey!);
        }
        return csrString
    }
    
    private func getPublicKeyChainData(tag : String) -> Data? {
        //Ask keychain to provide the publicKey in bits
        var query: [String: AnyObject] = [
            String(kSecClass): kSecClassKey,
            String(kSecAttrApplicationTag): self.publicKeyTag as AnyObject,
            String(kSecReturnData): kCFBooleanTrue
        ]
        
        query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrType

        var tempPublicKeyBits:AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &tempPublicKeyBits)

        switch result {
        case errSecSuccess:
            guard let keyBits = tempPublicKeyBits as? Data else {
                print("error in: convert to publicKeyBits")
                return nil
            }
            return keyBits
        default:
            print("error in: convert to publicKeyBits")
            return nil
        }
    }
    
    private func setAlgorithm(algorithm: String) -> Void {
        switch algorithm {
        case "SHA256withRSA":
            self.keyAlgorithm = .rsa(signatureType: .sha256)
        case "SHA512withRSA":
            self.keyAlgorithm = .rsa(signatureType: .sha512)
        case "SHA1withRSA":
            self.keyAlgorithm = .rsa(signatureType: .sha1)
        case "SHA256withECDSA":
            self.keyAlgorithm = .ec(signatureType: .sha256)
        case "SHA512withECDSA":
            self.keyAlgorithm = .ec(signatureType: .sha512)
        case "SHA1withECDSA":
            self.keyAlgorithm = .ec(signatureType: .sha1)
        default:
            self.keyAlgorithm = .rsa(signatureType: .sha1)
        }
    }
    
    public func deletePrivateKey(){
        var query: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrApplicationTag): self.privateKeyTag as AnyObject,
            String(kSecReturnRef)         : true as AnyObject
        ]
        
        query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrType
        let result = SecItemDelete(query as CFDictionary)
        
        if result != errSecSuccess{
            print("Error delete private key: \(result)")
            //            return nil
        }
    }
    
    public func encodedPublicKeyRSA() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPublicKey: String?
            self.performWithPublicKeyTag(tag: self.publicKeyTag!) { (publicKey) in
                encodedPublicKey = self.externalRepresentationForPublicKeyRSA(key: publicKey)
            }
            return encodedPublicKey;
        }
        if(self.publicKey == nil) { return nil }
        return self.externalRepresentationForPublicKeyRSA(key: self.publicKey!)
    }
    
    public func encodedPublicKeyDER() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPublicKey: String?
            self.performWithPublicKeyTag(tag: self.publicKeyTag!) { (publicKey) in
                encodedPublicKey = self.externalRepresentationForPublicKeyDER(key: publicKey)
            }
            return encodedPublicKey;
        }
        if(self.publicKey == nil) { return nil }
        return self.externalRepresentationForPublicKeyDER(key: self.publicKey!)
    }
    
    public func encodedPublicKey() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPublicKey: String?
            self.performWithPublicKeyTag(tag: self.publicKeyTag!) { (publicKey) in
                encodedPublicKey = self.externalRepresentationForPublicKey(key: publicKey)
            }
            return encodedPublicKey;
        }
        if(self.publicKey == nil) { return nil }
        return self.externalRepresentationForPublicKey(key: self.publicKey!)
    }
    
    public func encodedPrivateKeyRSA() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPrivateKey: String?
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!) { (privateKey) in
                encodedPrivateKey = self.externalRepresentationForPrivateKeyRSA(key: privateKey)
            }
            return encodedPrivateKey;
        }
        if(self.privateKey == nil) { return nil }
        return self.externalRepresentationForPrivateKeyRSA(key: self.privateKey!)
    }
    
    public func encodedPrivateKeyDER() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPrivateKey: String?
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!) { (privateKey) in
                encodedPrivateKey = self.externalRepresentationForPrivateKeyDER(key: privateKey)
            }
            return encodedPrivateKey;
        }
        if(self.privateKey == nil) { return nil }
        return self.externalRepresentationForPrivateKeyDER(key: self.privateKey!)
    }
    
    public func setPublicKey(publicKey: String) -> Bool? {
        guard let publicKeyStr = RSAECFormatter.stripHeaders(pemString: publicKey) else { return nil }
        let query: [String: AnyObject] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass): kSecAttrKeyClassPublic,
        ]
        print(publicKeyStr, "publicKeyStrpublicKeyStr")
        var error: Unmanaged<CFError>?
        guard let data = Data(base64Encoded: publicKeyStr, options: .ignoreUnknownCharacters) else { return nil }
        print(data, "datadatadata")

        guard let key = SecKeyCreateWithData(data as CFData, query as CFDictionary, &error) else { return nil }
        self.publicKey = key
        return true
    }
    
    public func setPrivateKey(privateKey: String) -> Bool? {
        guard let privateKeyStr = RSAECFormatter.stripHeaders(pemString: privateKey) else { return nil }
        let query: [String: AnyObject] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass): kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let data = Data(base64Encoded: privateKeyStr, options: .ignoreUnknownCharacters) else { return nil }
        guard let key = SecKeyCreateWithData(data as CFData, query as CFDictionary, &error) else { return nil }
        self.privateKey = key

        return true
    }
    
    public func encrypt64(message: String) -> String? {
        guard let data =  Data(base64Encoded: message, options: .ignoreUnknownCharacters) else { return nil }
        let encrypted = self._encrypt(data: data)
        return encrypted?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
    }

    public func encrypt(message: String) -> String? {
        guard let data =  message.data(using: .utf8) else { return nil }
        let encrypted = self._encrypt(data: data)
        return encrypted?.base64EncodedString(options: .lineLength64Characters)
    }
    
    public func _encrypt(data: Data) -> Data? {
        var cipherText: Data?
        
        // Closures
        let encryptor:SecKeyPerformBlock = { publicKey in
            let canEncrypt = SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionPKCS1)
            if(canEncrypt){
                var error: Unmanaged<CFError>?
                cipherText = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error) as Data?
            }
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPublicKeyTag(tag: self.publicKeyTag!, block: encryptor)
        } else {
            encryptor(self.publicKey!);
        }
        return cipherText;
    }
    
    public func decrypt64(message: String) -> String? {
        guard let data =  Data(base64Encoded: message, options: .ignoreUnknownCharacters) else { return nil }
        let decrypted = self._decrypt(data: data)
        return decrypted?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
    }
    
    public func decrypt(message: String) -> String? {
        guard let data =  Data(base64Encoded: message, options: .ignoreUnknownCharacters) else { return nil }
        let decrypted = self._decrypt(data: data)
        if (decrypted == nil) {
            return nil
        }
        return String(data: decrypted!, encoding: String.Encoding.utf8)
    }
    
    private func _decrypt(data: Data) -> Data? {
        var clearText: Data?
        let decryptor: SecKeyPerformBlock = {privateKey in
            let canEncrypt = SecKeyIsAlgorithmSupported(privateKey, .decrypt, .rsaEncryptionPKCS1)
            if(canEncrypt){
                var error: Unmanaged<CFError>?
                clearText = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, data as CFData, &error) as Data?
            }
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!, block: decryptor)
        } else {
            decryptor(self.privateKey!);
        }
        return clearText
    }
    
    public func sign64(b64message: String, withAlgorithm: String) -> String? {
        guard let data = Data(base64Encoded: b64message, options: .ignoreUnknownCharacters) else { return nil }
        let encodedSignature = self._sign(messageBytes: data, withAlgorithm: withAlgorithm, withEncodeOption: .lineLength64Characters)
        return encodedSignature
    }
    
    public func sign(message: String, withAlgorithm: String, withEncodeOption: NSData.Base64EncodingOptions) -> String? {
        guard let data =  message.data(using: .utf8) else { return nil }
        let encodedSignature = self._sign(messageBytes: data, withAlgorithm: withAlgorithm, withEncodeOption: withEncodeOption)
        return encodedSignature
    }
    
    private func _sign(messageBytes: Data, withAlgorithm: String, withEncodeOption: NSData.Base64EncodingOptions) -> String? {
        self.setAlgorithm(algorithm: withAlgorithm)
        var encodedSignature: String?
        let signer: SecKeyPerformBlock = { privateKey in
            // Build signature - step 1: SHA1 hash
            // Build signature - step 2: Sign hash
            //            var signature: Data? = nil
            var error: Unmanaged<CFError>?
            let signature = SecKeyCreateSignature(privateKey, self.keyAlgorithm.signatureAlgorithm, messageBytes as CFData, &error) as Data?
            
            if error != nil{
                print("Error in creating signature: \(error!.takeRetainedValue())")
            }
            
            encodedSignature = signature!.base64EncodedString(options: withEncodeOption)
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!, block: signer)
        } else {
            signer(self.privateKey!);
        }
        
        return encodedSignature
    }
    
    public func verify64(encodedSignature: String, withMessage: String, withAlgorithm: String) -> Bool? {
        guard let messageBytes =  Data(base64Encoded: encodedSignature, options: .ignoreUnknownCharacters) else { return nil }
        guard let signatureBytes = Data(base64Encoded: withMessage, options: .ignoreUnknownCharacters) else { return nil }
        return self._verify(signatureBytes: signatureBytes, withMessage: messageBytes, withAlgorithm: withAlgorithm)
    }
    
    public func verify(encodedSignature: String, withMessage: String, withAlgorithm: String) -> Bool? {
        guard let messageBytes =  withMessage.data(using: .utf8) else { return nil }
        guard let signatureBytes = Data(base64Encoded: encodedSignature, options: .ignoreUnknownCharacters) else { return nil }
        return self._verify(signatureBytes:signatureBytes , withMessage: messageBytes, withAlgorithm: withAlgorithm)
    }
    
    private func _verify(signatureBytes: Data, withMessage: Data, withAlgorithm: String) -> Bool? {
        var result = false
        self.setAlgorithm(algorithm: withAlgorithm)
        // Closures
        let verifier: SecKeyPerformBlock = { publicKey in
            var error: Unmanaged<CFError>?
            result = SecKeyVerifySignature(publicKey, self.keyAlgorithm.signatureAlgorithm, withMessage as CFData, signatureBytes as CFData, &error)
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPublicKeyTag(tag: self.publicKeyTag!, block: verifier)
        } else {
            verifier(self.publicKey!);
        }
        return result
    }
    
    private func performWithPrivateKeyTag(keyTag: String, block: SecKeyPerformBlock){
        var query: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrApplicationTag): keyTag as AnyObject,
            String(kSecReturnRef)         : true as AnyObject
        ]
        
        query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrType
        
        var result : AnyObject?
        
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            print("\(keyTag) Key existed!")
            block((result as! SecKey?)!)
        }
    }
    
    private func performWithPublicKeyTag(tag: String, block: SecKeyPerformBlock){
        self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!) { (privateKey) in
            let publicKey = SecKeyCopyPublicKey(privateKey)
            block(publicKey!)
        }
    }
    
    private func externalRepresentationForPublicKeyRSA(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPublicKeyRSA(publicKeyData: data)
    }
    
    private func externalRepresentationForPublicKey(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPublicKey(publicKeyData: data)
    }
    
    private func externalRepresentationForPublicKeyDER(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        let convertedData = RSAKeyEncoding().convertToX509EncodedKey(data)
        return RSAECFormatter.PEMFormattedPublicKey(publicKeyData: convertedData)
    }
    
    private func externalRepresentationForPrivateKeyRSA(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPrivateKeyRSA(privateKeyData: data)
    }
    
    private func externalRepresentationForPrivateKeyDER(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        let convertedData = RSAKeyEncoding().convertToX509EncodedKey(data)
        return RSAECFormatter.PEMFormattedPrivateKey(privateKeyData: convertedData)
    }
    
    private func externalRepresentationForPrivateKey(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPrivateKey(privateKeyData: data)
    }
    
    private func dataForKey(key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        var keyData: Data?

        keyData = SecKeyCopyExternalRepresentation(key, &error) as Data?

        if (keyData == nil) {
            print("error in dataForKey")
            return nil
        }

        return keyData;
    }
}

