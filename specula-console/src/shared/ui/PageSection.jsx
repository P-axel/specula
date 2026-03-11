export default function PageSection({ title, children, right }) {
  return (
    <section className="page-section">
      <div className="page-section-header">
        <h2>{title}</h2>
        {right ? <div>{right}</div> : null}
      </div>
      <div className="page-section-body">{children}</div>
    </section>
  );
}