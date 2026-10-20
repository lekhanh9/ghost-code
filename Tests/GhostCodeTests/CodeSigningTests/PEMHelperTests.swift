import XCTest
@testable import GhostCode

final class PEMHelperTests: XCTestCase {

    func testDecodePEMCertificate() {
        let fakeCertPEM = """
        -----BEGIN CERTIFICATE-----
        dGVzdC1jZXJ0aWZpY2F0ZS1kYXRh
        -----END CERTIFICATE-----
        """

        let decoded = PEMHelper.decode(pemString: fakeCertPEM, tag: "CERTIFICATE")
        XCTAssertEqual(decoded.count, 1)
        let stringContent = String(data: decoded[0], encoding: .utf8)
        XCTAssertEqual(stringContent, "test-certificate-data")
    }

    func testDecodePEMPrivateKey() {
        let fakeKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        dGVzdC1wcml2YXRlLWtleS1kYXRh
        -----END RSA PRIVATE KEY-----
        """

        let decoded = PEMHelper.decode(pemString: fakeKeyPEM, tag: "KEY")
        XCTAssertEqual(decoded.count, 1)
        let stringContent = String(data: decoded[0], encoding: .utf8)
        XCTAssertEqual(stringContent, "test-private-key-data")
    }

    func testDecodePEMMultipleBlocks() {
        let multiPEM = """
        -----BEGIN CERTIFICATE-----
        Y2VydDE=
        -----END CERTIFICATE-----
        Some commentary in between
        -----BEGIN CERTIFICATE-----
        Y2VydDI=
        -----END CERTIFICATE-----
        """

        let decoded = PEMHelper.decode(pemString: multiPEM, tag: "CERTIFICATE")
        XCTAssertEqual(decoded.count, 2)
        XCTAssertEqual(String(data: decoded[0], encoding: .utf8), "cert1")
        XCTAssertEqual(String(data: decoded[1], encoding: .utf8), "cert2")
    }

    func testLoadCertAndKeyHelpers() {
        let certPEM = """
        -----BEGIN CERTIFICATE-----
        AQIDBAU=
        -----END CERTIFICATE-----
        """
        let cert = PEMHelper.loadCertificate(from: certPEM.data(using: .utf8)!)
        XCTAssertNotNil(cert)

        let keyPEM = """
        -----BEGIN PRIVATE KEY-----
        AQIDBAU=
        -----END PRIVATE KEY-----
        """
        let key = PEMHelper.loadPrivateKey(from: keyPEM.data(using: .utf8)!)
        XCTAssertNotNil(key)
    }
}
