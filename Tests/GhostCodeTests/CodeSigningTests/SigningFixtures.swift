import Foundation
@testable import GhostCode

/// Throwaway certificates generated with OpenSSL for this test suite only (CA "Ghost Test CA",
/// leaf "iPhone Development: com.example.test"). They are not trusted for anything and exist so
/// the CMS builder can be exercised against a real DER issuer/serial.
enum SigningFixtures {
    static let leafBase64 = """
    MIIDrzCCApegAwIBAgIUTmwWuqnfyJVmCZxlRgAR1tbU2wQwDQYJKoZIhvcNAQELBQAwTTEWMBQGA1UEAwwNR2hvc3Qg\
    VGVzdCBDQTESMBAGA1UECwwJR2hvc3RUZXN0MRIwEAYDVQQKDAlHaG9zdFRlc3QxCzAJBgNVBAYTAlVTMB4XDTI2MTAy\
    MzEyMTY0MloXDTI5MDEyNTEyMTY0MlowZTEtMCsGA1UEAwwkaVBob25lIERldmVsb3BtZW50OiBjb20uZXhhbXBsZS50\
    ZXN0MRMwEQYDVQQLDApBQkNERTEyMzQ1MRIwEAYDVQQKDAlHaG9zdFRlc3QxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG\
    9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjb5WaFlMLcf8R0tqrbStGM/A/rJYEoc2oJZSyiK4XcjMI/AECxSJq13MoVWaHLyf\
    ZdHoU2T8cG5+eDDrzcUuwC1dhKNwaZ84OCnrYelo0zoOAwYcgOd3FDf/JsmKecXPG1H/53jsno+ZBuTs39NONQrm7cwf\
    L4HKa0NZdPUqjN4mFz81dQEndK69RihpiT8B6qTu2Eq/OQ88r2PU33A7iTotMDGsruYuFkx3YOGpdgbLnXWkkGHz88Iu\
    /Tj0xz8p/CxeZe4Klj17OS2s0w9cumqEmma4mg4e+JpwikrOLlx1KmLIUw/pJXDXPXGpsEKFEskLEFwge+QkjfcJOwYp\
    EwIDAQABo28wbTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU95ew\
    wzMb3TeYJmw1PwcKXRC+YFMwHwYDVR0jBBgwFoAU8ZcV08r1ngmf2saACsK2IVi29JowDQYJKoZIhvcNAQELBQADggEB\
    ALOqfGjyNBLNM3L+w90qPM+TjpsyRLFKHW4HC+cw9zOHPwKptHelXEvk6tGa5HRuS1xMtG69WNa48WJr5ZwbXdTPPA5p\
    jcT0fSH0cTch519PtWc+SMAOtfPrl3mTzd4w9f6V+AxcjjpwCCsYeAjjouHCUQ+f94qPXmtLRimZbCItiswPpkCTUmOW\
    2i1e+fGdENoVgXsFxRK8P1v+KfHySBMfdpP2CZZuM5bbStOoewYXlXC2ONbVKINA1wOlC5ERj14ZgbjgC8knEswWjH/S\
    x/uVzKrX1p9D+236pC33Q+GxAm0GKYWich7jsJJ7OcIIosf/CixrJziDjIg7/LGVKzo=
    """

    static let certificateChain: [Data] = {
        [leafBase64].compactMap { Data(base64Encoded: $0) }
    }()

    static var leafCertificate: Data {
        certificateChain.first ?? Data()
    }

    /// The CN zsign was given through the profile: `iPhone Development: com.example.test`.
    static let leafCommonName = "iPhone Development: com.example.test"
    static let teamID = "ABCDE12345"
    static let bundleID = "com.example.test"

    static func randomHash(_ size: Int) -> Data {
        Data((0..<size).map { UInt8($0 % 256) })
    }
}
