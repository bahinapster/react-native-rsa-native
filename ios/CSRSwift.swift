import Foundation
#if canImport(Security)
import Security
#endif


// swiftlint:disable:next type_body_length
public class CertificateSigningRequest : NSObject {
    private let sequenceTag: UInt8 = 0x30
    private let setTag: UInt8 = 0x31
    private var keyAlgorithm: KeyAlgorithm!
    private var attributes: NSDictionary
    private var subjectDER: Data?

    private var attributesMap = [
        "commonName": [0x06, 0x03, 0x55, 0x04, 0x03],
        "organizationName": [0x06, 0x03, 0x55, 0x04, 0x0A],
        "organizationUnitName": [0x06, 0x03, 0x55, 0x04, 0x0B],
        "countryName": [0x06, 0x03, 0x55, 0x04, 0x06],
        "stateOrProvinceName": [0x06, 0x03, 0x55, 0x04, 0x08],
        "localityName": [0x06, 0x03, 0x55, 0x04, 0x07],
        "emailAddress": [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01],
        "organizationIdentifier": [0x06, 0x03, 0x55, 0x04, 0x61],
        "title": [0x06, 0x03, 0x55, 0x04, 0x0C],
        "description": [0x06, 0x03, 0x55, 0x04, 0x0D],
        "givenName": [0x06, 0x03, 0x55, 0x04, 0x2A],
        "surname": [0x06, 0x03, 0x55, 0x04, 0x04]
    ] as [String : [UInt8]]

    public init(
        attributes: NSDictionary,
        keyAlgorithm: KeyAlgorithm
    ) {
        self.keyAlgorithm = keyAlgorithm
        self.attributes = attributes
    }

    public func build(_ publicKeyBits: Data, privateKey: SecKey, publicKey: SecKey?=nil) -> Data? {
        let certificationRequestInfo = buldCertificationRequestInfo(publicKeyBits)
        var signature = [UInt8](repeating: 0, count: 1024)
        var signatureLen: Int = signature.count

        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(privateKey,
                                                        keyAlgorithm.signatureAlgorithm,
                                                        certificationRequestInfo as CFData, &error) as Data? else {
            if error != nil {
                print("Error in creating signature: \(error!.takeRetainedValue())")
            }
            return nil
        }
        signatureData.copyBytes(to: &signature, count: signatureData.count)
        signatureLen = signatureData.count
        if publicKey != nil {
            if !SecKeyVerifySignature(publicKey!, keyAlgorithm.signatureAlgorithm,
                                      certificationRequestInfo as CFData, signatureData as CFData, &error) {
                print(error!.takeRetainedValue())
                return nil
            }
        }

        var certificationRequest = Data(capacity: 1024)
        certificationRequest.append(certificationRequestInfo)
        let shaBytes = keyAlgorithm.sequenceObjectEncryptionType
        certificationRequest.append(shaBytes, count: shaBytes.count)

        var signData = Data(capacity: 257)
        let zero: UInt8 = 0 // Prepend zero
        signData.append(zero)
        signData.append(signature, count: signatureLen)
        appendBITSTRING(signData, into: &certificationRequest)

        enclose(&certificationRequest, by: sequenceTag) // Enclose into SEQUENCE
        return certificationRequest
    }

    public func buildAndEncodeDataAsString(_ publicKeyBits: Data, privateKey: SecKey,
                                           publicKey: SecKey?=nil) -> String? {

        guard let buildData = self.build(publicKeyBits, privateKey: privateKey, publicKey: publicKey) else {
            return nil
        }

        return buildData.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
            .addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed)

    }

    public func buildCSRAndReturnString(_ publicKeyBits: Data, privateKey: SecKey, publicKey: SecKey?=nil) -> String? {

        guard let csrString = self.buildAndEncodeDataAsString(publicKeyBits,
                                                              privateKey: privateKey, publicKey: publicKey) else {
            return nil
        }

        let head = "-----BEGIN CERTIFICATE REQUEST-----\n"
        let foot = "-----END CERTIFICATE REQUEST-----\n"
        var isMultiple = false
        var newCSRString = head

        // Check if string size is a multiple of 64
        if csrString.count % 64 == 0 {
            isMultiple = true
        }

        for (integer, character) in csrString.enumerated() {
            newCSRString.append(character)

            if (integer != 0) && ((integer + 1) % 64 == 0) {
                newCSRString.append("\n")
            }

            if (integer == csrString.count-1) && !isMultiple {
                newCSRString.append("\n")
            }

        }

        newCSRString += foot

        return newCSRString
    }

    func buldCertificationRequestInfo(_ publicKeyBits: Data) -> Data {
        var certificationRequestInfo = Data(capacity: 256)

        // Add version
        let version: [UInt8] = [0x02, 0x01, 0x00] // ASN.1 Representation of integer with value 1
        certificationRequestInfo.append(version, count: version.count)

        // Add subject
        var subject = Data(capacity: 256)
        
        for item in self.attributesMap {
            let _value = self.attributes[item.key]
            if(_value != nil){
                appendSubjectItem(item.value, value: _value as! String, into: &subject)
            }
        }

        enclose(&subject, by: sequenceTag)// Enclose into SEQUENCE
        subjectDER = subject
        certificationRequestInfo.append(subject)

        // Add public key info
        let publicKeyInfo = buildPublicKeyInfo(publicKeyBits)
        certificationRequestInfo.append(publicKeyInfo)

        // Add attributes
        let attributes: [UInt8] = [0xA0, 0x00]
        certificationRequestInfo.append(attributes, count: attributes.count)
        enclose(&certificationRequestInfo, by: sequenceTag) // Enclose into SEQUENCE
        return certificationRequestInfo
    }

    // Utility class methods ...
    func buildPublicKeyInfo(_ publicKeyBits: Data) -> Data {

        var publicKeyInfo = Data(capacity: 390)

        switch keyAlgorithm! {
        case .rsa:
            publicKeyInfo.append(objectRSAEncryptionNULL, count: objectRSAEncryptionNULL.count)
        case .ec:
            publicKeyInfo.append(objectECPubicKey, count: objectECPubicKey.count)
            publicKeyInfo.append(objectECEncryptionNULL, count: objectECEncryptionNULL.count)
        }

        enclose(&publicKeyInfo, by: sequenceTag) // Enclose into SEQUENCE
        var publicKeyASN = Data(capacity: 260)
        switch keyAlgorithm! {
        case .ec:
            let key = getPublicKey(publicKeyBits)
            publicKeyASN.append(key)

        default:

            let mod = getPublicKeyMod(publicKeyBits)
            let integer: UInt8 = 0x02 // Integer
            publicKeyASN.append(integer)
            appendDERLength(mod.count, into: &publicKeyASN)
            publicKeyASN.append(mod)

            let exp = getPublicKeyExp(publicKeyBits)
            publicKeyASN.append(integer)
            appendDERLength(exp.count, into: &publicKeyASN)
            publicKeyASN.append(exp)

            enclose(&publicKeyASN, by: sequenceTag)// Enclose into ??
        }

        prependByte(0x00, into: &publicKeyASN) // Prepend 0 (?)
        appendBITSTRING(publicKeyASN, into: &publicKeyInfo)

        enclose(&publicKeyInfo, by: sequenceTag) // Enclose into SEQUENCE
        return publicKeyInfo
    }

    func appendSubjectItem(_ what: [UInt8], value: String, into: inout Data ) {

        if what.count != 5 && what.count != 11 {
            print("Error: appending to a non-subject item")
            return
        }

        var subjectItem = Data(capacity: 128)

        subjectItem.append(what, count: what.count)
        appendUTF8String(string: value, into: &subjectItem)
        enclose(&subjectItem, by: sequenceTag)
        enclose(&subjectItem, by: setTag)

        into.append(subjectItem)
    }

    func appendSubjectItemEmail(_ what: [UInt8], value: String, into: inout Data ) {

        if what.count != 5 && what.count != 11 {
            print("Error: appending to a non-subject item")
            return
        }

        var subjectItem = Data(capacity: 128)

        subjectItem.append(what, count: what.count)
        appendIA5String(string: value, into: &subjectItem)
        enclose(&subjectItem, by: sequenceTag)
        enclose(&subjectItem, by: setTag)

        into.append(subjectItem)
    }

    func appendUTF8String(string: String, into: inout Data) {

        let strType: UInt8 = 0x0C // UTF8STRING
        into.append(strType)
        appendDERLength(string.lengthOfBytes(using: String.Encoding.utf8), into: &into)
        into.append(string.data(using: String.Encoding.utf8)!)
    }

    func appendIA5String(string: String, into: inout Data) {

        let strType: UInt8 = 0x16 // IA5String
        into.append(strType)
        appendDERLength(string.lengthOfBytes(using: String.Encoding.utf8), into: &into)
        into.append(string.data(using: String.Encoding.utf8)!)
    }

    func appendDERLength(_ length: Int, into: inout Data) {

        assert(length < 0x8000)

        if length < 128 {
            let dLength = UInt8(length)
            into.append(dLength)

        } else if length < 0x100 {

            var dLength: [UInt8] = [0x81, UInt8(length & 0xFF)]
            into.append(&dLength, count: dLength.count)

        } else if length < 0x8000 {

            let preRes: UInt = UInt(length & 0xFF00)
            let res = UInt8(preRes >> 8)
            var dLength: [UInt8] = [0x82, res, UInt8(length & 0xFF)]
            into.append(&dLength, count: dLength.count)
        }
    }

    func appendBITSTRING(_ data: Data, into: inout Data) {

        let strType: UInt8 = 0x03 // BIT STRING
        into.append(strType)
        appendDERLength(data.count, into: &into)
        into.append(data)
    }

    // swiftlint:disable:next identifier_name
    func enclose(_ data: inout Data, by: UInt8) {

        var newData = Data(capacity: data.count + 4)

        newData.append(by)
        appendDERLength(data.count, into: &newData)
        newData.append(data)

        data = newData
    }

    func prependByte(_ byte: UInt8, into: inout Data) {

        var newData = Data(capacity: into.count + 1)

        newData.append(byte)
        newData.append(into)

        into = newData
    }

    func getPublicKey(_ publicKeyBits: Data) -> Data {

        // Current only supports uncompressed keys, 65=1+32+32
        var iterator = 0

        _ = derEncodingSpecificSize(publicKeyBits, at: &iterator, numOfBytes: 8)

        let range: Range<Int> = 0 ..< 65

        return publicKeyBits.subdata(in: range)
    }

    // swiftlint:disable:next line_length
    // From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c
    func getPublicKeyExp(_ publicKeyBits: Data) -> Data {

        var iterator = 0

        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator) // Total size
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        iterator += modSize

        iterator+=1 // TYPE - bit stream exp
        let expSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)

        let range: Range<Int> = iterator ..< (iterator + expSize)

        return publicKeyBits.subdata(in: range)
    }

    func getPublicKeyMod(_ publicKeyBits: Data) -> Data {

        var iterator = 0

        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)

        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)

        let range: Range<Int> = iterator ..< (iterator + modSize)

        return publicKeyBits.subdata(in: range)
    }

    func derEncodingSpecificSize(_ buf: Data, at iterator: inout Int, numOfBytes: Int) -> Int {

        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)

        if data[0] != 0x04 {
            print("Error, framework only supports uncompressed keys")
        }

        return buf.count
    }

    func derEncodingGetSizeFrom(_ buf: Data, at iterator: inout Int) -> Int {

        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)

        var itr = iterator
        var numOfBytes = 1
        var ret = 0

        if data[itr] > 0x80 {
            numOfBytes = Int((data[itr] - 0x80))
            itr += 1
        }

        for index in 0 ..< numOfBytes {
            ret = (ret * 0x100) + Int(data[itr + index])
        }

        iterator = itr + numOfBytes

        return ret
    }
} // swiftlint:disable:this file_length
