export default function PageHero({ eyebrow, title, description, badge }) {
  return (
    <section className="soc-hero">
      <div>
        {eyebrow ? <p className="soc-hero-kicker">{eyebrow}</p> : null}
        <h1 className="soc-hero-title">{title}</h1>
        {description ? <p className="soc-hero-text">{description}</p> : null}
      </div>

      {badge ? <div className="soc-health-pill">{badge}</div> : null}
    </section>
  );
}