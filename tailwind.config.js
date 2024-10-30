/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/main/resources/templates/**/*.{html,js}"],
  theme: {
    extend: {
      backgroundImage: {
        image: "url('https://trip.s3-hcm-r1.s3cloud.vn/landing/TVC.svg')",
        notFound: "url('/images/error.svg')",
        logo: "url('/images/Logo.svg')"
      },
      colors: {
        loginBackground: "#fff",
        notice: "#31AFD7",
        formBackground: "rgba(255, 255, 255)",
        errorBackground: "rgb(9, 25, 54)",
        label: "rgba(1,1,1,0.7)",
        placeHolder: "rgba(1,1,1,0.2)",
        primary: "rgba(14, 165, 233, 0.3)",
        customBack: "rgba(14, 165, 233, 0.5)",
        buttonColor: "#0ea5e9"
      },
      fontFamily: {
        comfortaa: ["Comfortaa", "sans-serif"],
        inter: ["Inter", "sans-serif"]
      }
    }
  },
  plugins: [],
}

