# Spike: a Secure Enclave key that signs only when the person is present

Run on 2026-09-29 on a Mac with an M4 Pro and Touch ID, macOS 27.0 (build 26A428), Swift 6.4, with no code-signing identities, so the tool was ad-hoc signed.

## The question

Can a command-line tool, without an Apple developer certificate or entitlements, hold a key that signs only when the person touches Touch ID (or enters their password)? erehold needs this so that accepting a changed mode, and later loosening anything, needs a living person rather than any code running as the user.

## Results

| Step | Result |
|---|---|
| A permanent Secure Enclave key in the keychain (`create-a`) | Refused, error -34018: the tool lacks the entitlement the keychain requires |
| A Secure Enclave key kept as an encrypted blob in a file (`create-b`) | Created, no entitlements needed; the blob is usable only by this Mac's Secure Enclave |
| Signing with prompts forbidden (`sign-noprompt`) | Refused: "User interaction is required" |
| Signing with the person's touch (`sign`) | Signed |
| Checking that signature against the public key (`verify`) | Valid |
| The same signature against a message changed by one character | Invalid |
| Signing again with prompts forbidden, just after a touch | Still refused, so a touch does not leave the key open for other programs |

So path B works: a key only the Secure Enclave can use signs only with the person present, and anyone holding the public key can check the signature later.

## The limit it shows

The wording of the Touch ID prompt is written by the program that asks. This spike wrote "sign an erehold spike message"; a hostile program running as the user could write anything. Presence proves that a person touched, not what they approved. Binding the approval to exactly what was shown needs a display the attacker cannot draw on.

## Running it

```
swiftc -O spike.swift -o spike && codesign -s - -f spike
./spike create-a
./spike create-b key.blob
./spike sign-noprompt key.blob
./spike sign key.blob
./spike verify <public key hex> "erehold spike: sign this mode hash" <signature hex>
```

The key blob and the compiled tool are not kept in the repository: the blob belongs to one Mac, and the tool is rebuilt from source.
