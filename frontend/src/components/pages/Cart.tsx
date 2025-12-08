import Footer from "../layout/Footer";
import Header from "../layout/Header";
import { products } from "../../data/products";

const productsSublist = [...products].sort(() => Math.random() - 0.5).slice(0, 2);

export default function Cart() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header showIcons={true} />
      <div className="flex flex-col items-center flex-1 my-20">
        <div className="container">
          <div>
            <div className="flex flex-col gap-10">
              <div className="flex justify-between items-center">
                <p className="flex-1/4">Product</p>
                <p className="flex-1/4 text-center">Price</p>
                <p className="flex-1/4 text-center">Quantity</p>
                <p className="flex-1/4 text-right">Subtotal</p>
              </div>
              {productsSublist.map((product, index) => {
                return (
                  <div key={index} className="flex justify-between items-center">
                    <div className="flex-1/4 flex gap-4 items-center">
                      <img src={product.image} className="w-12 h-12 object-contain" />
                      <p>{product.name}</p>
                    </div>
                    <p className="flex-1/4 text-center">${product.price}</p>
                    <div className="flex-1/4 flex justify-center">
                      <input
                        type="number"
                        className="text-center border border-[#B3B3B3] block w-20 p-2 rounded-sm"
                        min={1}
                      />
                    </div>
                    <p className="flex-1/4 text-right">${product.price}</p>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="flex justify-between gap-4 mt-15">
            <button className="font-medium border border-[#B3B3B3] py-4 px-10 rounded-sm cursor-pointer hover:bg-[#DB444411]">
              Return To Shop
            </button>
            <button className="font-medium border border-[#B3B3B3] py-4 px-10 rounded-sm cursor-pointer hover:bg-[#DB444411]">
              Update Cart
            </button>
          </div>
          <div className="flex justify-between items-start gap-4 mt-15">
            <div className="flex gap-4">
              <input
                type="text"
                placeholder="Coupon Code"
                className="border text-sm block w-60 p-3 rounded-sm font-medium"
              />
              <button className="py-3 px-10 text-sm font-medium bg-[#DB4444] text-white rounded-sm cursor-pointer hover:opacity-90">
                Apply Coupon
              </button>
            </div>
            <div className="border p-4 rounded-sm min-w-120 text-sm">
              <p className="font-semibold text-lg">Cart Total</p>
              <div className="flex justify-between gap-4 opacity-75 mt-5">
                <p className="font-medium">Subtotal: </p>
                <p className="font-medium">
                  ${productsSublist.reduce((acc, product) => acc + product.price, 0).toFixed(2)}
                </p>
              </div>
              <hr className="my-3 border-[#B3B3B3]" />
              <div className="flex justify-between gap-4 opacity-75">
                <p className="font-medium">Shipping: </p>
                <p className="font-medium">Free</p>
              </div>
              <hr className="my-3 border-[#B3B3B3]" />
              <div className="flex justify-between gap-4 opacity-75">
                <p className="font-medium">Total: </p>
                <p className="font-medium">
                  ${productsSublist.reduce((acc, product) => acc + product.price, 0).toFixed(2)}
                </p>
              </div>
              <div className="flex justify-center mt-5">
                <button className="py-3 px-10 text-sm font-medium bg-[#DB4444] text-white rounded-sm cursor-pointer hover:opacity-90">
                  Proceed To Checkout
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}
