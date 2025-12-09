import cartIcon from "../../assets/icon-cart.svg";
import trashIcon from "../../assets/icon-trash.svg";
import { products } from "../../data/products";

const productsSublist = [...products].sort(() => Math.random() - 0.5).slice(0, 4);

export default function WishListProducts() {
  return (
    <div className="flex flex-col items-center my-20">
      <div className="container">
        <div className="flex justify-between gap-4 items-center">
          <p className="text-xl font-[Inter]">Wishlist (4)</p>
          <button className="border border-[#B3B3B3] py-4 px-10 rounded-sm cursor-pointer hover:bg-[#DB444411]">Move All To Bag</button>
        </div>
        <div className="grid gap-10 grid-cols-[repeat(auto-fit,minmax(250px,1fr))] mt-15">
          {productsSublist.map((product, index) => {
            return (
              <div key={index} className="flex flex-col gap-2 relative snap-start cursor-pointer">
                <div className="bg-[#F5F5F5] h-[250px] shrink-0 p-12  relative">
                  <img src={product.image} className="w-full h-full object-contain" />
                  {product.discount > 0 && (
                    <div className="bg-[#DB4444] w-12 h-6 rounded-sm absolute text-[12px] top-3 left-3 text-white flex justify-center items-center">
                      -{Math.round((product.discount / product.price) * 100)}%
                    </div>
                  )}
                  <button className="absolute top-3 right-3 w-8 h-8 p-0.5 rounded-full flex justify-center items-center bg-white cursor-pointer hover:invert-10 duration-100">
                    <img src={trashIcon} />
                  </button>
                  <button className="absolute bottom-0 left-0 right-0 bg-black text-white justify-center py-2 font-medium cursor-pointer flex items-center gap-2 hover:opacity-80">
                    <img className="invert w-6" src={cartIcon} />
                    <p className="text-sm">Add To Cart</p>
                  </button>
                </div>
                <p className="font-semibold truncate w-full">{product.name}</p>
                <div className="flex gap-2 items-center">
                  <p className="text-[#DB4444] font-semibold">${(product.price - product.discount).toFixed(2)}</p>
                  <p
                    className="text-[#808080] font-semibold line-through"
                    style={{ display: product.discount > 0 ? "block" : "none" }}
                  >
                    ${product.price}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
