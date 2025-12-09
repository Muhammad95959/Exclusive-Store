import paymentsImage from "../../assets/payments-image.png";
import { products } from "../../data/products";
import Footer from "../layout/Footer";
import Header from "../layout/Header";

const productsSublist = [...products].sort(() => Math.random() - 0.5).slice(0, 2);

export default function Checkout() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header showIcons={true} />
      <div className="flex flex-col items-center flex-1 my-20">
        <div className="container">
          <form className="flex justify-between gap-4 items-start">
            <div>
              <h2 className="text-3xl font-medium font-[Inter]">Billing Details</h2>
              <div className="mt-10 text-medium">
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="firstname">
                    First Name<span className="text-[#DB4444]">*</span>
                  </label>
                  <input required type="text" id="firstname" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="companyname">
                    Company Name
                  </label>
                  <input type="text" id="companyname" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="streetaddress">
                    Street Adress<span className="text-[#DB4444]">*</span>
                  </label>
                  <input required type="text" id="streetaddress" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="appartment">
                    Appartment, floor, etc.
                  </label>
                  <input type="text" id="appartment" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="city">
                    Town/City<span className="text-[#DB4444]">*</span>
                  </label>
                  <input required type="text" id="city" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="phonenumber">
                    Phone Number<span className="text-[#DB4444]">*</span>
                  </label>
                  <input required type="text" id="phonenumber" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5">
                  <label className="opacity-60 text-sm" htmlFor="emailaddress">
                    Email Address<span className="text-[#DB4444]">*</span>
                  </label>
                  <input required type="text" id="emailaddress" className="bg-[#F5F5F5] p-3 w-full mt-3 rounded-sm" />
                </div>
                <div className="mt-5 flex items-center">
                  <input
                    defaultChecked
                    type="checkbox"
                    id="saveinfo"
                    className="appearance-none w-4 h-4 border rounded-xs checked:bg-[#DB4444] checked:border-[#DB4444] checked:before:content-['✔'] checked:before:text-[10px] checked:before:text-white checked:before:flex checked:before:items-center checked:before:justify-center"
                  />
                  <label htmlFor="saveinfo" className="text-sm pl-5">
                    Save this information for faster check-out next time
                  </label>
                </div>
              </div>
            </div>
            <div className="p-4 rounded-sm min-w-120 mt-24">
              <div className="flex flex-col gap-5">
                {productsSublist.map((product, index) => {
                  return (
                    <div key={index} className="flex justify-between items-center gap-4">
                      <div className="flex gap-4 items-center">
                        <img src={product.image} className="w-12 h-12 object-contain" />
                        <p className="max-w-[320px]">{product.name}</p>
                      </div>
                      <p>${product.price}</p>
                    </div>
                  );
                })}
              </div>
              <div className="mt-10">
                <div className="flex justify-between gap-4 opacity-75">
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
              </div>
              <div className="flex flex-col gap-5 mt-10">
                <div className="flex items-center justify-between">
                  <div>
                    <input type="radio" id="bank" name="payment" />
                    <label htmlFor="bank" className="pl-4">
                      Bank
                    </label>
                  </div>
                  <img src={paymentsImage} />
                </div>
                <div className="flex items-center">
                  <input defaultChecked type="radio" id="cash" name="payment" />
                  <label htmlFor="cash" className="pl-4">
                    Cash on delivery
                  </label>
                </div>
              </div>
              <div className="flex gap-4 mt-10">
                <input
                  type="text"
                  placeholder="Coupon Code"
                  className="border text-sm block w-60 p-3 rounded-sm font-medium"
                />
                <button className="py-4 px-15 text-sm font-medium bg-[#DB4444] text-white rounded-sm cursor-pointer hover:opacity-90">
                  Apply Coupon
                </button>
              </div>
              <button
                type="submit"
                className="mt-5 py-4 px-15 text-sm font-medium bg-[#DB4444] text-white rounded-sm cursor-pointer hover:opacity-90"
              >
                Place Order
              </button>
            </div>
          </form>
        </div>
      </div>
      <Footer />
    </div>
  );
}
