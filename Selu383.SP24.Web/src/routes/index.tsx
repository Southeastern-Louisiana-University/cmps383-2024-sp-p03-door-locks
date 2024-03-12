import { Link } from "react-router-dom";

export default function Home() {
  return (
    <div className="flex justify-center">
      <div className="flex gap-2 flex-col">
        <h1 className="mt-10">Tests:</h1>
        <Link className="text-blue-500 cursor-pointer underline" to="/enroll-example">
          Enrollment
        </Link>
        <Link className="text-blue-500 cursor-pointer underline" to="/lock-scanner">
          Lock Scanner
        </Link>
      </div>
    </div>
  );
}
