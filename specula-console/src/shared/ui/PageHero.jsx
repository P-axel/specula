import "./PageHero.css";

export default function PageHero({ eyebrow, title, description, badge }) {
  return (
    <section className="page-hero">
      <div className="page-hero__top">
        {eyebrow ? <p className="page-hero__eyebrow">{eyebrow}</p> : <span />}
        {badge ? <div className="page-hero__badge">{badge}</div> : null}
      </div>

      <div className="page-hero__content">
        <h1 className="page-hero__title">{title}</h1>
        {description ? (
          <p className="page-hero__description">{description}</p>
        ) : null}
      </div>
    </section>
  );
}