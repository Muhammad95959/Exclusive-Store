import { Link } from "react-router-dom";

export default function Footer() {
  return (
    <div className="bg-black p-6 flex items-center justify-center">
      <div className="container">
        <div className="container flex gap-10 justify-between border-b border-[#B3B3B3] pb-6">
          <div className="text-white">
            <div className="font-[Inter] font-bold text-4xl h-10">XStore</div>
            <p className="font-medium mt-4 max-w-[600px]">
              Exclusive Store is a sleek online store focused on premium tech products, offering curated smartphones, laptops,
              and smart-home gadgets. It’s the go-to spot for anyone looking to upgrade their digital setup.
            </p>
          </div>
          <div className="text-white">
            <p className="font-semibold text-2xl h-10 flex items-center">Quick Links</p>
            <ul className="mt-4 grid gap-2 font-medium">
              <li className="hover:underline">
                <Link to="/">Home</Link>
              </li>
              <li className="hover:underline">
                <Link to="/contact">Contact</Link>
              </li>
              <li className="hover:underline">
                <Link to="/about">About</Link>
              </li>
              <li className="hover:underline">
                <Link to="/signup">Sign Up</Link>
              </li>
            </ul>
          </div>
          <div></div>
        </div>
        <p className="text-[#B3B3B3] text-center pt-6 font-medium">
          Copyright 2025 &copy; XStore - Created by {" "}
          <a target="_blank" href="https://github.com/Muhammad95959" className="text-cyan-300 hover:underline">Muhammad Hefzey</a>
        </p>
      </div>
    </div>
  );
}
