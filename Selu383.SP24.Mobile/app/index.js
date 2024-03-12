import "react-native-get-random-values";
import QRCode from "react-native-qrcode-svg";
import { StatusBar } from "expo-status-bar";
import { StyleSheet, Text, View } from "react-native";
import { ed25519 } from "@noble/curves/ed25519";
import { useEffect, useState } from "react";
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { CBOR } from "cbor-redux";

export default function App() {
  const [signedBytes, setSignedBytes] = useState(null);

  useEffect(() => {
    const now = new Date();
    const start = new Date(now.valueOf() - 1000 * 60 * 60);
    const end = new Date(now.valueOf() + 1000 * 60 * 60 * 24 * 2000);

    const deviceKeyPrivate = ed25519.utils.randomPrivateKey();
    const deviceKeyPublic = ed25519.getPublicKey(deviceKeyPrivate);

    const requestSco = {
      // the publicDeviceKey in hex format
      deviceKeyHex: bytesToHex(deviceKeyPublic),

      // lock end-user should have access, "*" can be used for all locks
      lock: "123",

      // identity (name) of the end user, lock access will be logged with this
      identity: "Matt",

      // when access should start (ISO 8601 format)
      start: start.toISOString(),

      // when access should end (ISO 8601 format)
      end: end.toISOString(),
    };

    // Please note: this shouldn't be here - and should be called from the access control server
    fetch("https://door-lock.azurewebsites.net/api/issue-sco", {
      method: "post",
      body: JSON.stringify(requestSco),
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((x) => x.text())
      .then((x) => {
        // the SCO in hex format
        const openLockJson = { s: hexToBytes(x), t: now.valueOf() };
        const openLockBytes = new Uint8Array(CBOR.encode(openLockJson));
        const openLockSignature = ed25519.sign(openLockBytes, deviceKeyPrivate);
        const openLockSignedArray = [openLockBytes, openLockSignature];
        const openLockSignedBytes = new Uint8Array(CBOR.encode(openLockSignedArray));
        setSignedBytes(openLockSignedBytes);
      })
      .catch((e) => {
        console.error(e);
      });
  }, []);
  return (
    <View style={styles.container}>
      {signedBytes ? (
        <>
          <Text>LQR:</Text>
          <QRCode value={[{ data: "lqr:/" }, { data: signedBytes, mode: "byte" }]} ecl="L" size={300} quietZone={10} />
        </>
      ) : null}
      <StatusBar style="auto" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
