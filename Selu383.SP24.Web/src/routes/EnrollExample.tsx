import { FormEvent, useState } from "react";
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { ed25519 } from "@noble/curves/ed25519";
import { CBOR } from "cbor-redux";
import QRCode from "qrcode";
import { Link } from "react-router-dom";

export default function EnrollExample() {
  const [deviceKey, setDeviceKey] = useState(ed25519.utils.randomPrivateKey());
  const [scoHex, setScoHex] = useState("");

  const [qrData, setQrData] = useState("");

  const [identity, setIdentity] = useState("Matt");
  const [lock, setLock] = useState("123");
  const [start, setStart] = useState(
    new Date(Date.parse(new Date().toDateString()) + 1000 * 60 * 60 * 6).toISOString().replace("Z", "")
  );
  const [end, setEnd] = useState(
    new Date(Date.parse(new Date().toDateString()) + 1000 * 60 * 60 * 30).toISOString().replace("Z", "")
  );

  return (
    <div className="flex justify-center items-center gap-10 flex-wrap mt-20 flex-col">
      <Link className="text-blue-500 cursor-pointer underline" to="/lock-scanner">
        Lock Scanner
      </Link>
      <form className="flex flex-col gap-8 border-solid border rounded-lg border-gray-200 p-8" onSubmit={handleSubmit}>
        <div className="grid grid-cols-[auto_15rem] gap-2">
          <label className="text-right" htmlFor="num">
            <span>lock:</span>
          </label>
          <input
            id="number"
            className="border-b text-right outline-none"
            value={lock}
            onChange={(e) => setLock(e.target.value ?? "")}
          />
          <label className="text-right" htmlFor="ide">
            <span>identity:</span>
          </label>
          <input
            id="identity"
            className="border-b text-right outline-none"
            value={identity}
            onChange={(e) => setIdentity(e.target.value ?? "")}
          />
          <label className="text-right" htmlFor="sta">
            <span>start:</span>
          </label>
          <input
            id="start"
            className="border-b text-right outline-none"
            value={start}
            type="datetime-local"
            onChange={(e) => setStart(e.target.value)}
          />
          <label className="text-right" htmlFor="end">
            <span>end:</span>
          </label>
          <input
            id="end"
            className="border-b text-right outline-none"
            value={end}
            type="datetime-local"
            onChange={(e) => setEnd(e.target.value)}
          />
        </div>
        <button className="m-auto bg-slate-100  rounded-md px-4 py-2 cursor-pointer" type="submit">
          Enroll
        </button>
      </form>
      {scoHex ? (
        <div className="flex flex-col gap-8 border-solid border rounded-lg border-gray-200 p-8">
          <div>
            <p>Private key:</p>
            <span className="font-mono">{bytesToHex(deviceKey)}</span>
            <p>SCO:</p>
            <div>
              <pre className="text-clip overflow-clip w-20 inline-block font-mono">{scoHex}</pre>
              <span>...</span>
              <pre className="text-clip overflow-clip w-20 inline-block font-mono" style={{ direction: "rtl" }}>
                {scoHex}
              </pre>
            </div>
          </div>
          <div>{qrData ? <img src={qrData} /> : null}</div>
          <button
            className="m-auto mb-0 bg-slate-100  rounded-md px-4 py-2 cursor-pointer"
            type="button"
            onClick={handlePresent}
          >
            {qrData ? "Regenerate" : "Present"}
          </button>
        </div>
      ) : null}
    </div>
  );

  function handlePresent() {
    const now = new Date();
    const openLockJson = { s: hexToBytes(scoHex), t: now.valueOf() };
    const openLockBytes = new Uint8Array(CBOR.encode(openLockJson));
    const openLockSignedArray = [openLockBytes, ed25519.sign(openLockBytes, deviceKey)];
    const openLockSignedBytes = new Uint8Array(CBOR.encode(openLockSignedArray));
    const encoder = new TextEncoder();

    QRCode.toDataURL(
      [
        {
          data: encoder.encode("lqr:/"),
          mode: "byte",
        },
        {
          data: openLockSignedBytes,
          mode: "byte",
        },
      ],
      {
        errorCorrectionLevel: "L",
      }
    ).then((d) => {
      setQrData(d);
    });
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const newDevicePrivateKey = ed25519.utils.randomPrivateKey();

    setDeviceKey(newDevicePrivateKey);
    setQrData("");

    const requestSco = {
      // the publicDeviceKey in hex format
      deviceKeyHex: bytesToHex(ed25519.getPublicKey(newDevicePrivateKey)),

      // lock end-user should have access, "*" can be used for all locks
      lock: lock,

      // identity (name) of the end user, lock access will be logged with this
      identity: "Matt",

      // when access should start (ISO 8601 format)
      start: new Date(Date.parse(start)).toISOString(),

      // when access should end (ISO 8601 format)
      end: new Date(Date.parse(end)).toISOString(),
    };

    // Please note: this shouldn't be here - and should be called from the access control server

    fetch("/api/issue-sco", {
      method: "post",
      body: JSON.stringify(requestSco),
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((x) => x.text())
      .then((x) => {
        // the SCO in hex format
        setScoHex(x);
      });
  }
}
