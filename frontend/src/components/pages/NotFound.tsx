import { Link } from "react-router-dom";
import Footer from "../layout/Footer";
import Header from "../layout/Header";

export default function NotFound() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header showIcons={true} />
      <div className="flex-1 flex flex-col justify-center items-center">
        <h1 className="font-medium text-8xl font-[Inter] tracking-widest">404 Not Found</h1>
        <p className="mt-7.5 text-sm">
          The page you are looking for is not found. You may want to go back to the homepage
        </p>
        <Link
          to="/"
          className="mt-15 py-4 px-10 text-sm font-medium bg-[#DB4444] text-white rounded-sm cursor-pointer hover:opacity-90"
        >
          Back to home page
        </Link>
      </div>
      <Footer />
    </div>
  );
}
