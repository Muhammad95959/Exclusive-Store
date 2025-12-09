import { Link } from "react-router-dom";
import cartIcon from "../../assets/icon-cart.svg";
import heartIcon from "../../assets/icon-heart.svg";
import searchIcon from "../../assets/icon-search.svg";

export default function Header(props: { showIcons: boolean }) {
  return (
    <div className="border-b border-[#B3B3B3] py-6 flex items-center justify-center">
      <div className="container flex justify-between items-center">
        <div className="font-[Inter] font-bold text-2xl">XStore</div>
        <ul className="flex gap-12">
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
        <div className="flex items-center gap-6">
          <div className="relative">
            <input
              type="text"
              placeholder="What are you looking for?"
              className="bg-[#F5F5F5] px-4 py-2 text-sm max-w-65"
            />
            <img src={searchIcon} className="absolute top-[50%] right-4 translate-y-[-50%]" />
          </div>
          {props.showIcons && (
            <>
              <button>
                <img src={heartIcon} />
              </button>
              <Link to="/cart">
                <img src={cartIcon} />
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
