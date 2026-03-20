export default function InitialLoadingScreen() {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        background:
          "linear-gradient(135deg, #081120 0%, #0d1b2a 45%, #10253a 100%)",
        color: "#eaf4ff",
        padding: "24px",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "420px",
          textAlign: "center",
          padding: "32px",
          borderRadius: "20px",
          background: "rgba(255, 255, 255, 0.04)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.28)",
          backdropFilter: "blur(10px)",
        }}
      >
        <div
          style={{
            width: "54px",
            height: "54px",
            margin: "0 auto 18px",
            borderRadius: "50%",
            border: "4px solid rgba(255,255,255,0.15)",
            borderTopColor: "#5ab0ff",
            animation: "soc-spin 0.9s linear infinite",
          }}
        />

        <h1
          style={{
            margin: 0,
            fontSize: "1.35rem",
            fontWeight: 700,
            letterSpacing: "0.2px",
          }}
        >
          Chargement des données SOC
        </h1>

        <p
          style={{
            marginTop: "10px",
            marginBottom: 0,
            color: "rgba(234, 244, 255, 0.78)",
            lineHeight: 1.6,
            fontSize: "0.98rem",
          }}
        >
          Initialisation des incidents et alertes. 
          
        </p>
      </div>

      <style>
        {`
          @keyframes soc-spin {
            to {
              transform: rotate(360deg);
            }
          }
        `}
      </style>
    </div>
  );
}