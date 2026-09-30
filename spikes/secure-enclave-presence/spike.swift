// Spike: can an ad-hoc-signed command-line tool hold a Secure Enclave key that needs the
// person's presence to use? Two paths are tried.
//   A. keychain: SecKeyCreateRandomKey with the Secure Enclave token and a permanent item
//   B. blob:     CryptoKit SecureEnclave key; its dataRepresentation (an opaque blob only this
//                Mac's Secure Enclave can use) is written to a file, no keychain involved
// Subcommands:
//   create-a                 path A
//   create-b <blobfile>      path B, writes the blob and prints the public key
//   sign-noprompt <blobfile> tries to sign with interaction forbidden (must FAIL without presence)
//   sign <blobfile>          signs with a Touch ID prompt (run by hand)
//   verify <pubhex> <msg> <sighex>

import Foundation
import CryptoKit
import LocalAuthentication
import Security

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) -> Data {
  var d = Data(); var i = s.startIndex
  while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
  return d
}
func access() -> SecAccessControl {
  var err: Unmanaged<CFError>?
  let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                           [.privateKeyUsage, .userPresence], &err)
  if ac == nil { print("access control FAILED: \(err!.takeRetainedValue())"); exit(1) }
  return ac!
}
let message = Data("erehold spike: sign this mode hash".utf8)
let args = CommandLine.arguments

switch args.count > 1 ? args[1] : "" {
case "create-a":
  let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: Data("dev.erehold.spike".utf8),
      kSecAttrAccessControl as String: access(),
    ],
  ]
  var err: Unmanaged<CFError>?
  if SecKeyCreateRandomKey(attrs as CFDictionary, &err) != nil { print("A: permanent Secure Enclave key CREATED in the keychain") }
  else { print("A: FAILED: \(err!.takeRetainedValue())") }
case "create-b":
  do {
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access())
    try key.dataRepresentation.write(to: URL(fileURLWithPath: args[2]))
    print("B: Secure Enclave key created; blob written (\(key.dataRepresentation.count) bytes)")
    print("B: public key \(hex(key.publicKey.rawRepresentation))")
  } catch { print("B: FAILED: \(error)") }
case "sign-noprompt":
  do {
    let ctx = LAContext(); ctx.interactionNotAllowed = true
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(contentsOf: URL(fileURLWithPath: args[2])), authenticationContext: ctx)
    let sig = try key.signature(for: message)
    print("NOPROMPT: SIGNED WITHOUT PRESENCE (gate did not hold): \(hex(sig.derRepresentation))")
  } catch { print("NOPROMPT: refused without presence, as required: \(error)") }
case "sign":
  do {
    let ctx = LAContext(); ctx.localizedReason = "sign an erehold spike message"
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(contentsOf: URL(fileURLWithPath: args[2])), authenticationContext: ctx)
    let sig = try key.signature(for: message)
    print("SIGN: signed with presence")
    print("SIGN: signature \(hex(sig.derRepresentation))")
  } catch { print("SIGN: FAILED: \(error)") }
case "verify":
  do {
    let pub = try P256.Signing.PublicKey(rawRepresentation: unhex(args[2]))
    let sig = try P256.Signing.ECDSASignature(derRepresentation: unhex(args[4]))
    print(pub.isValidSignature(sig, for: Data(args[3].utf8)) ? "VERIFY: valid" : "VERIFY: INVALID")
  } catch { print("VERIFY: FAILED: \(error)") }
default:
  print("usage: spike create-a | create-b <blob> | sign-noprompt <blob> | sign <blob> | verify <pubhex> <msg> <sighex>")
}
