import jsQR from "jsqr";
import { useCallback, useEffect, useRef, useState } from "react";
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { ed25519 } from "@noble/curves/ed25519";
import { CBOR } from "cbor-redux";
import { Link } from "react-router-dom";

const serverPublicKey = hexToBytes("649fefe0574c8e26792f2634a7f4b2b26986514a20fab9408c66b8f8319c6085");

interface DebugInfo {
  error?: string;
  lockAccess?: string;
  identity?: string;
  startAccess?: string;
  endAccess?: string;
}

export default function LockScanner() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  const [unlocked, setUnlocked] = useState(false);
  const [debugInfo, setDebugInfo] = useState<DebugInfo | null>(null);

  const reset = useCallback(() => {
    setUnlocked(false);
    setDebugInfo(null);
  }, []);

  useEffect(() => {
    const video = videoRef.current;
    const canvasElement = canvasRef.current;
    if (!video || !canvasElement) {
      return;
    }

    const canvas = canvasElement.getContext("2d", { willReadFrequently: true });
    if (!canvas) {
      return;
    }

    const abortController = new AbortController();
    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then(function (stream) {
      video.srcObject = stream;
      video.play();
      requestAnimationFrame(tick);
    });

    return () => {
      abortController.abort();
      video.pause();
    };
    function tick() {
      if (abortController.signal.aborted) {
        return;
      }
      if (!video || !canvasElement || !canvas) {
        return;
      }
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvasElement.height = video.videoHeight;
        canvasElement.width = video.videoWidth;
        canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
        const imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert",
        });

        if (code?.chunks?.length) {
          setUnlocked((c) => {
            try {
              if (c) {
                // don't process if we are already unlocked
                return c;
              }

              if (code.chunks.length !== 2) {
                setDebugInfo({ error: "Expected two chunks" });
                return false;
              }

              if (!code.data.startsWith("lqr:/")) {
                setDebugInfo({ error: "Expected QR to start with lqr:/" });
                return false;
              }

              if (!("bytes" in code.chunks[1])) {
                setDebugInfo({ error: "Expected QR to have Byte mode in second chunk" });
                return false;
              }

              const openLockSigned = new Uint8Array(code.chunks[1].bytes);

              const openLockArray = CBOR.decode(openLockSigned.buffer);
              if (!Array.isArray(openLockArray) || openLockArray.length !== 2) {
                setDebugInfo({ error: "Expected openLockArray with two elements" });
                return false;
              }

              if (!(openLockArray[0] instanceof Uint8Array) || !(openLockArray[1] instanceof Uint8Array)) {
                setDebugInfo({ error: "Expected openLockArray's elements to be Uint8Array" });
                return false;
              }

              const openLockBytes = openLockArray[0];
              const openLockSignature = openLockArray[1];
              const openLockJson = CBOR.decode(openLockBytes.buffer) as object;
              if (
                !("s" in openLockJson && openLockJson.s instanceof Uint8Array) ||
                !("t" in openLockJson && typeof openLockJson.t === "number")
              ) {
                setDebugInfo({ error: "Expected openLockJson to have an s and t value" });
                return false;
              }

              const sco = openLockJson.s;
              const scoArray = CBOR.decode(sco.buffer) as Array<unknown>;
              if (!Array.isArray(scoArray) || scoArray.length !== 2) {
                setDebugInfo({ error: "Expected signedLockArray with two elements" });
                return false;
              }

              if (!(scoArray[0] instanceof Uint8Array) || !(scoArray[1] instanceof Uint8Array)) {
                setDebugInfo({ error: "Expected signedLockArray's elements to be Uint8Array" });
                return false;
              }

              const scoBytes = scoArray[0];
              const scoSignature = scoArray[1];
              const scoJson = CBOR.decode(scoBytes.buffer) as object;

              if (!("p" in scoJson && scoJson.p instanceof Uint8Array)) {
                setDebugInfo({ error: "Expected scoJson to have an 'p' property of type Uint8Array" });
                return false;
              }

              if (!("l" in scoJson && typeof scoJson.l === "string")) {
                setDebugInfo({ error: "Expected scoJson to have an 'l' property of type string" });
                return false;
              }

              if (!("i" in scoJson && typeof scoJson.i === "string")) {
                setDebugInfo({ error: "Expected scoJson to have an 'i' property of type string" });
                return false;
              }

              if (!("s" in scoJson && typeof scoJson.s === "number")) {
                setDebugInfo({ error: "Expected scoJson to have an 's' property of type number" });
                return false;
              }

              if (!("e" in scoJson && typeof scoJson.e === "number")) {
                setDebugInfo({ error: "Expected scoJson to have an 'e' property of type number" });
                return false;
              }

              const now = new Date();
              const start = new Date(scoJson.s);
              const end = new Date(scoJson.e);
              const debugInfo: DebugInfo = {
                identity: scoJson.i,
                lockAccess: scoJson.l,
                startAccess: start.toLocaleString(),
                endAccess: end.toLocaleString(),
              };

              if (Math.abs(now.valueOf() - openLockJson.t) > 1000 * 60 * 60 * 5) {
                debugInfo.error =
                  "openLock timesamp 't' is more than 5 minutes 'off' (is your mobile device's time correct?)";
                setDebugInfo(debugInfo);
                return false;
              }

              if (now < start) {
                debugInfo.error = "now < start of lock access";
                setDebugInfo(debugInfo);
                return false;
              }

              if (end < now) {
                debugInfo.error = "end < now of lock access";
                setDebugInfo(debugInfo);
                return false;
              }

              if (!ed25519.verify(scoSignature, scoBytes, serverPublicKey, { zip215: false })) {
                debugInfo.error = "Invalid server signature";
                setDebugInfo(debugInfo);
                return false;
              }

              if (!ed25519.verify(openLockSignature, openLockBytes, scoJson.p, { zip215: false })) {
                debugInfo.error = "Invalid device signature";
                setDebugInfo(debugInfo);
                return false;
              }

              const requestKey = bytesToHex(openLockSignature);
              if (localStorage.getItem(requestKey)) {
                debugInfo.error = "Duplicate request - barcodes work only once";
                setDebugInfo(debugInfo);
                return false;
              }

              localStorage.setItem(requestKey, "1");
              setDebugInfo(debugInfo);

              return true;
            } catch (e) {
              console.error(e);
              setDebugInfo({ error: "Unknown failure" });
              return false;
            }
          });
        }
      }
      setTimeout(() => {
        if (abortController.signal.aborted) {
          return;
        }
        requestAnimationFrame(tick);
      }, 100);
    }
  }, [reset]);

  return (
    <div className="flex flex-col justify-center items-center gap-10 mt-20 ">
      <Link className="text-blue-500 cursor-pointer underline" to="/enroll-example">
        Enrollment
      </Link>
      <div className="flex justify-center gap-20 flex-wrap">
        <div className="flex gap-2 flex-col items-center ">
          <p>Lock camera:</p>
          <video ref={videoRef} className="w-80 h-80" />
        </div>

        <div className="flex gap-2 flex-col items-center ">
          <p>Lock</p>
          <LockState unlocked={unlocked} />
          {unlocked ? (
            <button type="button" className="text-blue-500 cursor-pointer" onClick={reset}>
              Click To Lock
            </button>
          ) : null}
          {debugInfo ? <pre className="whitespace-pre-wrap w-full">{JSON.stringify(debugInfo, null, 2)}</pre> : null}
        </div>
        <canvas ref={canvasRef} className="hidden" />
      </div>
    </div>
  );
}

function LockState({ unlocked }: { unlocked: boolean }) {
  return !unlocked ? (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth={1.5}
      stroke="currentColor"
      className="w-24 h-24 text-red-500"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"
      />
    </svg>
  ) : (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth={1.5}
      stroke="currentColor"
      className="w-24 h-24 text-green-400"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M13.5 10.5V6.75a4.5 4.5 0 1 1 9 0v3.75M3.75 21.75h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H3.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"
      />
    </svg>
  );
}
