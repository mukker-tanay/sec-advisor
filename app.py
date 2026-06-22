"""SecAdvisor Streamlit UI: free-text Q&A and stack-exposure lookup, both showing sources."""
import streamlit as st

from rag_chain import answer_question, get_llm, get_vector_store
from stack_exposure import check_stack_exposure, load_records

st.set_page_config(page_title="SecAdvisor", page_icon="🛡️")


@st.cache_resource
def load_qa_resources():
    return get_vector_store(), get_llm()


@st.cache_resource
def load_stack_records():
    return load_records()


st.title("🛡️ SecAdvisor")
st.caption("RAG over a static NVD CVE snapshot. Answers are grounded and cited, or refused if not in the data.")

tab_qa, tab_stack = st.tabs(["Ask a question", "Check my stack"])

with tab_qa:
    question = st.text_input("Ask about a security advisory", placeholder="Is there a known issue with Sendmail's debug command?")
    if st.button("Ask", key="ask_button") and question:
        vector_store, llm = load_qa_resources()
        with st.spinner("Retrieving and generating..."):
            answer, sources = answer_question(question, vector_store, llm)
        st.markdown(f"**Answer:** {answer}")

        if sources:
            with st.expander(f"Sources used ({len(sources)})"):
                for s in sources:
                    st.markdown(f"- **{s['cve_id']}** ({s['severity']}, CVSS {s['cvss_score']}): {s['description']}")
        else:
            st.caption("No sources retrieved -- this is why the answer was a refusal.")

with tab_stack:
    techs_input = st.text_area(
        "List your stack (one per line or comma-separated)",
        placeholder="sendmail\nsunos\nopenssl 3.0",
    )
    if st.button("Check exposure", key="check_button") and techs_input:
        techs = [t.strip() for t in techs_input.replace(",", "\n").splitlines() if t.strip()]
        records = load_stack_records()
        results = check_stack_exposure(techs, records)

        st.write(f"Checked: {', '.join(techs)}")
        if not results:
            st.success("No known advisories matched any listed tech in this snapshot.")
        else:
            st.warning(f"{len(results)} matching advisories found, ranked by severity.")
            for r in results:
                with st.expander(f"[{r['severity']} {r['cvss_score']}] {r['cve_id']} (matched: {', '.join(r['matched_techs'])})"):
                    st.write(r["description"])
                    if r["references"]:
                        st.write("References:")
                        for ref in r["references"]:
                            st.markdown(f"- {ref}")
