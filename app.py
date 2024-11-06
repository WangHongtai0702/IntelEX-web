import streamlit as st
import streamlit.components.v1 as components
from src.ttp import analyse_procedure, query_graphrag, analyse_ttp
from src.rule import generate_rules
from src.utils import draw_ttp_tree
import random
import json
import os
import nltk

st.set_page_config(layout="wide")


def page_ttp(if_demo: bool = False, if_procedure: bool = False):
    if 'ttp_results' not in st.session_state:
        st.session_state.ttp_results = None
    if 'rules_results' not in st.session_state:
        st.session_state.rules_results = None
    if 'rules_results_without_ttp' not in st.session_state:
        st.session_state.rules_results_without_ttp = None

    col1, col2, col3 = st.columns([2, 3, 3])
    with col1:
        attack_report = st.text_area("Paste your attack report here", height=600)

    if st.button("Analyze TTP"):
        if attack_report:
            if if_demo:
                ttps = json.load(open("results/demo.json", "r", encoding="utf-8"))
                st.session_state.ttp_results = ttps['ttps']
            else:
                # 调用分析函数
                st.session_state.ttp_results = analyse_ttp(attack_report, if_procedure)['ttps_with_rag_with_filter']  # 保存 TTP 结果到 session_state
                with open("results/demo.json", "w", encoding="utf-8") as f:
                    json.dump({'ttps': st.session_state.ttp_results}, f, ensure_ascii=False, indent=4)
    if st.session_state.ttp_results:
        i = 0
        for ttp in st.session_state.ttp_results:
            if i % 2 == 0:
                col = col2
            else:
                col = col3
            with col:
                procedures_html = "<br>".join([f"&bull; {proc}" for proc in ttp['procedure']])
                st.markdown(f"""
                        <div style="background-color: #fffdee; padding: 15px; margin-bottom: 15px; 
                                    border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
                            <p style="margin: 0;"><strong>Tactic:</strong> {ttp['tactic']}</p>
                            <p style="margin: 0;"><strong>Technique:</strong> {ttp['technique']}</p>
                            <p style="margin: 0;"><strong>Procedure:</strong> <br>{procedures_html}</p>
                            <p style="margin: 0;"><strong>Entity:</strong> <br>{ttp['entity']}</p>
                            <p style="margin: 0;"><strong>Reason:</strong> <br>{ttp['reason']}</p>
                        </div>
                        """, unsafe_allow_html=True)
            i += 1
    if st.session_state.ttp_results:
        draw_ttp_tree(st.session_state.ttp_results)
        with open("results/ttp_tree.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        # Display the HTML content in Streamlit
        components.html(html_content, height=800, width=1000)

    st.markdown('---')
    col1, col2 = st.columns([1, 1])
    with col2:
        if st.session_state.ttp_results and st.button("Analyze Rules with TTPs"):
            # 调用分析 rules 函数
            st.session_state.rules_results = generate_rules(attack_report, st.session_state.ttp_results, rule_type='splunk')["rules"]
        if st.session_state.rules_results:
            st.markdown("<h3>Rules Analysis</h3>", unsafe_allow_html=True)
            for i, rule in enumerate(st.session_state.rules_results):
                st.markdown(f"<p><strong>Rule {i + 1}:</strong> {rule}</p>", unsafe_allow_html=True)
    with col1:
        if st.button("Analyse Rules without TTPs"):
            st.session_state.rules_results_without_ttp= generate_rules(attack_report, None, rule_type='splunk')["rules"]
        if st.session_state.rules_results_without_ttp:
            st.markdown("<h3>Rules Analysis without TTPs</h3>", unsafe_allow_html=True)
            for i, rule in enumerate(st.session_state.rules_results_without_ttp):
                st.markdown(f"<p><strong>Rule {i + 1}:</strong> {rule}</p>", unsafe_allow_html=True)


def page_chatbot():
    if "message" not in st.session_state:
        st.session_state.message = []
    for message in st.session_state.message:
        with st.chat_message(message['role']):
            st.markdown(message['content'])
    if prompt := st.chat_input("Input your message here"):
        with st.chat_message('user'):
            st.markdown(prompt)
        st.session_state.message.append({'role': 'user', 'content': prompt})
        # chatbot response
        with st.spinner('Generating...'):
            response = query_graphrag(prompt)
        with st.chat_message('assistant'):
            st.markdown(response)
        st.session_state.message.append({'role': 'assistant', 'content': response})


def main():
    # st.title('GenTTPs')
    # page = st.sidebar.selectbox("Select a page", ["TTP Analysis", "Chatbot"])
    page = 'TTP Analysis'
    api_key_openai = st.sidebar.text_input(
        "OpenAI API Key",
        st.session_state.get("OPENAI_API_KEY", ""),
        type="password",
    )
    model_openai = st.sidebar.selectbox(
        "OpenAI Model",
        ("gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"),
    )
    settings = {
        "model": model_openai,
        "model_provider": "openai",
        "temperature": 0.3,
    }
    st.session_state["OPENAI_API_KEY"] = api_key_openai
    os.environ["OPENAI_API_KEY"] = st.session_state["OPENAI_API_KEY"]
    os.environ["MODEL_NAME"] = settings["model"]
    if st.session_state["OPENAI_API_KEY"]:
        with open(".env", "w", encoding="utf-8") as f:
            f.write(f'GRAPHRAG_API_KEY={st.session_state["OPENAI_API_KEY"]}\n')
    # 根据选择加载相应的页面
    if page == "TTP Analysis":
        page_ttp()
    elif page == "Chatbot":
        page_chatbot()


if __name__ == '__main__':
    main()

