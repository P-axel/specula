import "./PageSection.css";

export default function PageSection({ title, children, right }) {
  return (
    <section className="page-section">
      <div className="page-section__header">
        <h2 className="page-section__title">{title}</h2>
        {right ? <div className="page-section__actions">{right}</div> : null}
      </div>

      <div className="page-section__content">
        {children}
      </div>
    </section>
  );
}