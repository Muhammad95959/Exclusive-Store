import heroImage from "../../assets/hero-image.jpg";

export default function Hero() {
  return (
    <div className="justify-center items-center flex gap-6">
      <div className="container flex justify-start gap-10">
        <ul className="border-r border-[#0000004d] pt-8 pr-20 flex flex-col gap-6 justify-center">
          <li>
            <a>Phones</a>
          </li>
          <li>
            <a>Computers</a>
          </li>
          <li>
            <a>SmartWatch</a>
          </li>
          <li>
            <a>Camera</a>
          </li>
          <li>
            <a>Headphones</a>
          </li>
          <li>
            <a>Gaming</a>
          </li>
        </ul>
        <div className="flex-1">
          <div className="flex items-center justify-around px-10 py-5 bg-black mt-8">
            <p className="text-white font-medium text-5xl leading-normal">
              Up to 30%
              <br /> off Voucher
            </p>
            <div className="image w-[400px]">
              <img src={heroImage} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
