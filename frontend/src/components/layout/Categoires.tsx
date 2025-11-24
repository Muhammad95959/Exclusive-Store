import { useState } from "react";
import cameraIcon from "../../assets/icon-camera.svg";
import computerIcon from "../../assets/icon-computer.svg";
import gamingIcon from "../../assets/icon-gaming.svg";
import headphoneIcon from "../../assets/icon-headphone.svg";
import phoneIcon from "../../assets/icon-phone.svg";
import smartwatchIcon from "../../assets/icon-smartwatch.svg";
import RedHeader from "../ui/RedHeader";

const categories = [
  { name: "Phones", icon: phoneIcon },
  { name: "Computers", icon: computerIcon },
  { name: "SmartWatch", icon: smartwatchIcon },
  { name: "Camera", icon: cameraIcon },
  { name: "Headphones", icon: headphoneIcon },
  { name: "Gaming", icon: gamingIcon },
];

export default function Categories() {
  const [selected, setSelected] = useState("");

  function handleCategoryChange(name: string) {
    setSelected((oldName) => (oldName === name ? "" : name));
  }

  return (
    <div>
      <RedHeader>Categories</RedHeader>
      <div className="flex justify-center mb-20">
        <div className="container border-b border-[#B3B3B3] pb-20">
          <div className="font-semibold text-4xl font-[Inter] tracking-wider mb-15">Browse By Category</div>
          <div className="flex gap-6">
            {categories.map((category) => {
              return (
                <button
                  className="border border-[#B3B3B3] flex-1 aspect-square flex justify-center items-center flex-col gap-4 cursor-pointer"
                  onClick={() => handleCategoryChange(category.name)}
                  style={{ backgroundColor: selected === category.name ? "#DB4444" : "transparent" }}
                >
                  <img
                    className="w-[40%]"
                    src={category.icon}
                    style={{ filter: selected === category.name ? "invert(1)" : "none" }}
                  />
                  <p style={{ color: selected === category.name ? "white" : "black" }}>{category.name}</p>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
