import searchIcon from "../../assets/icon-search.svg";
import heartIcon from "../../assets/icon-heart.svg";
import cartIcon from "../../assets/icon-cart.svg";
import { Link } from "react-router-dom";

export default function Header() {
  return (
    <div className="border-b border-[#0000004d] py-6 flex items-center justify-center">
      <div className="container flex justify-between items-center">
        <div className="font-[Inter] font-bold text-2xl">Exclusive</div>
        <ul className="flex gap-12">
          <li><Link to="/">Home</Link></li>
          <li><Link to="/contact">Contact</Link></li>
          <li><Link to="/about">About</Link></li>
          <li><Link to="/signup">Sign Up</Link></li>
        </ul>
        <div className="flex items-center gap-6">
          <div className="relative">
            <input type="text" placeholder="What are you looking for?" className="bg-[#F5F5F5] px-4 py-2 text-sm max-w-65" />
            <img src={searchIcon} className="absolute top-[50%] right-4 translate-y-[-50%]" />
          </div>
          <button>
            <img src={heartIcon} />
          </button>
          <button>
            <img src={cartIcon} />
          </button>
        </div>
      </div>
    </div>
  );
}
