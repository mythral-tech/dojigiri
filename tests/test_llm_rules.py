"""Tests for LLM security rules — prompt injection, output sinks, agent safety.

Each rule gets at least one positive test (should trigger) and one negative test
(should NOT trigger). Grouped by category into classes.
"""

import pytest
from dojigiri.detector import run_regex_checks


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  security.yaml — cross-language prompt injection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPromptInjectionFstring:
    def test_triggers_python(self):
        code = 'system_prompt = f"You are {persona}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-fstring" for f in findings)

    def test_triggers_javascript(self):
        code = 'system_prompt = f"You are {persona}"\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = 'system_prompt = "You are a helper"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-fstring" for f in findings)


class TestPromptInjectionFormat:
    def test_triggers_python(self):
        code = 'prompt = "Help {}".format(topic)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-format" for f in findings)

    def test_triggers_javascript(self):
        code = 'prompt = "Help {}".format(topic)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-format" for f in findings)

    def test_no_trigger_static(self):
        code = 'prompt = "Help with math"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-format" for f in findings)


class TestPromptInjectionConcat:
    def test_triggers_python(self):
        code = 'system_message = "You are " + role\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-concat" for f in findings)

    def test_triggers_javascript(self):
        code = 'system_message = "You are " + role\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-concat" for f in findings)

    def test_no_trigger_static(self):
        code = 'system_message = "You are a helper"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-concat" for f in findings)


class TestPromptInjectionPercent:
    def test_triggers_python(self):
        code = 'prompt = "Tell me about %s" % topic\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-percent" for f in findings)

    def test_no_trigger_static(self):
        code = 'prompt = "Tell me about cats"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-percent" for f in findings)


class TestPromptInjectionTemplateLiteral:
    def test_triggers_js(self):
        code = 'systemPrompt = `You are ${role}`\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-template-literal" for f in findings)

    def test_no_trigger_static_js(self):
        code = 'systemPrompt = "static"\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-template-literal" for f in findings)


class TestPromptInjectionContentFstring:
    def test_triggers(self):
        code = '"content": f"Hello {user}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-content-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = '"content": "Hello world"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-content-fstring" for f in findings)


class TestPromptInjectionContentTemplate:
    def test_triggers_js(self):
        code = '"content": `Hello ${user}`\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-content-template" for f in findings)

    def test_no_trigger_static_js(self):
        code = '"content": "Hello"\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-content-template" for f in findings)


class TestPromptInjectionSystemRoleFstring:
    def test_triggers(self):
        code = '{"role": "system", "content": f"You are {x}"}\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-system-role-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = '{"role": "system", "content": "static"}\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-system-role-fstring" for f in findings)


class TestPromptInjectionSystemRoleTemplate:
    def test_triggers_js(self):
        code = "role: 'system', content: `Do ${thing}`\n"
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-system-role-template" for f in findings)

    def test_no_trigger_static_js(self):
        code = 'role: \'system\', content: "static"\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-system-role-template" for f in findings)


class TestPromptInjectionUrlToPrompt:
    def test_triggers(self):
        code = 'resp = requests.get(url)\nprompt = resp.text\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-url-to-prompt" for f in findings)

    def test_no_trigger_parsed(self):
        code = 'resp = requests.get(url)\ndata = json.loads(resp.text)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-url-to-prompt" for f in findings)


class TestPromptInjectionFileToPrompt:
    def test_triggers(self):
        code = 'content = file.read()\nmessages += content\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-file-to-prompt" for f in findings)

    def test_no_trigger_parsed(self):
        code = 'content = file.read()\ndata = json.loads(content)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-file-to-prompt" for f in findings)


class TestPromptInjectionDbToPrompt:
    def test_triggers(self):
        code = 'row = cursor.fetchone()\nprompt = row[0]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-db-to-prompt" for f in findings)

    def test_no_trigger_different_var(self):
        code = 'row = cursor.fetchone()\nuser_id = row[0]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-db-to-prompt" for f in findings)


class TestPromptInjectionFormatLocals:
    def test_triggers(self):
        code = 'prompt_text.format(**locals())\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-format-locals" for f in findings)

    def test_no_trigger_explicit_kwargs(self):
        code = 'prompt_text.format(name=name)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-format-locals" for f in findings)


class TestPromptInjectionFormatMapLocals:
    def test_triggers(self):
        code = 'message.format_map(locals())\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-format-map-locals" for f in findings)

    def test_no_trigger_explicit_dict(self):
        code = 'message.format_map({"key": "val"})\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-format-map-locals" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  security.yaml — LLM safety controls
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLlmSafetyDisabledGoogle:
    def test_triggers(self):
        code = 'threshold = HarmBlockThreshold.BLOCK_NONE\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-safety-disabled-google" for f in findings)

    def test_no_trigger_enabled(self):
        code = 'threshold = HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-safety-disabled-google" for f in findings)


class TestLlmSafetyDisabledCohere:
    def test_triggers(self):
        code = 'safety_mode="NONE"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-safety-disabled-cohere" for f in findings)

    def test_no_trigger_contextual(self):
        code = 'safety_mode="CONTEXTUAL"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-safety-disabled-cohere" for f in findings)


class TestLlmSafetyDisabledMistral:
    def test_triggers(self):
        code = 'safe_prompt=False\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-safety-disabled-mistral" for f in findings)

    def test_no_trigger_enabled(self):
        code = 'safe_prompt=True\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-safety-disabled-mistral" for f in findings)


class TestLlmTemperatureMax:
    def test_triggers(self):
        code = 'temperature=2.0,\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-temperature-max" for f in findings)

    def test_no_trigger_normal(self):
        code = 'temperature=0.7,\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-temperature-max" for f in findings)


class TestLlmClientControlledMessages:
    def test_triggers(self):
        code = 'msgs = request.json["messages"]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-client-controlled-messages" for f in findings)

    def test_no_trigger_wrapped(self):
        code = 'msgs = [{"role":"user","content": request.json["input"]}]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-client-controlled-messages" for f in findings)


class TestLlmRoleFromUserInput:
    def test_triggers(self):
        code = '"role": request.form["role"]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-role-from-user-input" for f in findings)

    def test_no_trigger_hardcoded(self):
        code = '"role": "user"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-role-from-user-input" for f in findings)


class TestLlmSecretInPrompt:
    def test_triggers(self):
        code = 'system_prompt = f"Use key {api_key}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-secret-in-prompt" for f in findings)

    def test_no_trigger_safe_var(self):
        code = 'system_prompt = f"Help {username}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-secret-in-prompt" for f in findings)


class TestLlmConnectionStringInPrompt:
    def test_triggers(self):
        code = 'prompt = "Connect to postgres://user:pass@host/db"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-connection-string-in-prompt" for f in findings)

    def test_no_trigger_safe(self):
        code = 'prompt = "Connect to the database"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-connection-string-in-prompt" for f in findings)


class TestLlmLangchainPythonRepl:
    def test_triggers(self):
        code = 'repl = PythonREPL()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-langchain-python-repl" for f in findings)

    def test_no_trigger_safe(self):
        code = 'repl = SafeREPL()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-langchain-python-repl" for f in findings)


class TestLlmLangchainBash:
    def test_triggers(self):
        code = 'shell = BashProcess()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-langchain-bash" for f in findings)

    def test_no_trigger_safe(self):
        code = 'shell = RestrictedShell()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-langchain-bash" for f in findings)


class TestLlmAgentUnboundedLoop:
    def test_triggers(self):
        code = 'while True:\n    resp = chat.completions.create(model="gpt-4")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-agent-unbounded-loop" for f in findings)

    def test_no_trigger_bounded(self):
        code = 'for i in range(10):\n    resp = chat.completions.create()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-agent-unbounded-loop" for f in findings)


class TestLlmToolCallToExec:
    def test_triggers(self):
        code = 'args = tool_calls[0].arguments\nexec(args)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-tool-call-to-exec" for f in findings)

    def test_no_trigger_validated(self):
        code = 'args = tool_calls[0].arguments\nvalidated = validate(args)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-tool-call-to-exec" for f in findings)


class TestLlmToolCallToSql:
    def test_triggers(self):
        code = 'sql = function.arguments\ncursor.execute(sql)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-tool-call-to-sql" for f in findings)

    def test_no_trigger_no_tool_calls(self):
        code = 'sql = user_query\ncursor.execute(sql)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-tool-call-to-sql" for f in findings)


class TestLlmUntrustedModelLoad:
    def test_triggers(self):
        code = 'AutoModel.from_pretrained(request.args.get("model"))\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-untrusted-model-load" for f in findings)

    def test_no_trigger_hardcoded(self):
        code = 'AutoModel.from_pretrained("bert-base")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-untrusted-model-load" for f in findings)


class TestLlmModelDownloadUrl:
    def test_triggers(self):
        code = 'model = AutoModel.from_pretrained(f"hf/{name}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-model-download-url" for f in findings)

    def test_no_trigger_static(self):
        code = 'model = AutoModel.from_pretrained("gpt2")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-model-download-url" for f in findings)


class TestLlmAutoApproveTools:
    def test_triggers(self):
        code = 'auto_approve=True\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-auto-approve-tools" for f in findings)

    def test_no_trigger_approval_required(self):
        code = 'require_approval=True\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-auto-approve-tools" for f in findings)


class TestLlmAgentUnrestrictedTools:
    def test_triggers(self):
        code = 'tools=get_all_tools()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-agent-unrestricted-tools" for f in findings)

    def test_no_trigger_explicit_list(self):
        code = 'tools=[search_tool, calc_tool]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-agent-unrestricted-tools" for f in findings)


class TestLlmSystemPromptLogged:
    def test_triggers(self):
        code = 'logger.info(f"Prompt: {system_prompt}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-system-prompt-logged" for f in findings)

    def test_no_trigger_safe_log(self):
        code = 'logger.info("Request received")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-system-prompt-logged" for f in findings)


class TestLlmSystemPromptReturned:
    def test_triggers(self):
        code = 'return jsonify({"prompt": system_prompt})\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-system-prompt-returned" for f in findings)

    def test_no_trigger_safe_response(self):
        code = 'return jsonify({"status": "ok"})\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-system-prompt-returned" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  python.yaml — Python-specific LLM rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPromptInjectionOpenAIFstring:
    def test_triggers(self):
        code = 'chat.completions.create(messages=[{"content":f"Tell me about {topic}"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-openai-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = 'chat.completions.create(messages=[{"content":"Tell me about dogs"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-openai-fstring" for f in findings)


class TestPromptInjectionOpenAIFormat:
    def test_triggers(self):
        code = 'ChatCompletion.create(messages=[{"content":"Hello {}".format(user_input)}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-openai-format" for f in findings)

    def test_no_trigger_static(self):
        code = 'ChatCompletion.create(messages=[{"content":"Hello world"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-openai-format" for f in findings)


class TestPromptInjectionAnthropicFstring:
    def test_triggers(self):
        code = 'client.messages.create(model="claude", messages=[{"content":f"Analyze {data}"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-anthropic-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = 'client.messages.create(model="claude", messages=[{"content":"Analyze this"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-anthropic-fstring" for f in findings)


class TestPromptInjectionAnthropicFormat:
    def test_triggers(self):
        code = 'messages.create(\n  messages=[{"content": "Hello {}".format(user)}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-anthropic-format" for f in findings)

    def test_no_trigger_static(self):
        code = 'messages.create(messages=[{"content":"Hello"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-anthropic-format" for f in findings)


class TestPromptInjectionAnthropicConcat:
    def test_triggers(self):
        code = 'messages.create(\n  messages=[{"content": "Hello " + user}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-anthropic-concat" for f in findings)

    def test_no_trigger_static(self):
        code = 'messages.create(messages=[{"content":"Hello"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-anthropic-concat" for f in findings)


class TestPromptInjectionLangchainFstring:
    def test_triggers(self):
        code = 'PromptTemplate(f"You are a {role} assistant")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-langchain-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = 'PromptTemplate("You are a helpful assistant")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-langchain-fstring" for f in findings)


class TestPromptInjectionLangchainSystemVar:
    def test_triggers(self):
        code = 'SystemMessage(content=f"You are {role}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-langchain-system-var" for f in findings)

    def test_no_trigger_static(self):
        code = 'SystemMessage(content="You are a helper")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-langchain-system-var" for f in findings)


class TestPromptInjectionLitellm:
    def test_triggers(self):
        code = 'litellm.completion(model="gpt-4", messages=[{"content":f"Do {task}"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-litellm" for f in findings)

    def test_no_trigger_static(self):
        code = 'litellm.completion(model="gpt-4", messages=[{"content":"Do task"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-litellm" for f in findings)


class TestPromptInjectionGenai:
    def test_triggers(self):
        code = 'model.generate_content(f"Explain {concept}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-genai" for f in findings)

    def test_no_trigger_static(self):
        code = 'model.generate_content("Explain gravity")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-genai" for f in findings)


class TestPromptInjectionCohere:
    def test_triggers(self):
        code = 'co.chat(message=f"Help with {query}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-cohere" for f in findings)

    def test_no_trigger_static(self):
        code = 'co.chat(message="Help with math")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-cohere" for f in findings)


class TestPromptInjectionLlamaindexFstring:
    def test_triggers(self):
        code = 'PromptTemplate(template=f"Summarize {doc}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-llamaindex-fstring" for f in findings)

    def test_no_trigger_static(self):
        code = 'PromptTemplate(template="Summarize the document")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-llamaindex-fstring" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  python.yaml — LLM output sinks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLlmOutputToExec:
    def test_triggers(self):
        code = 'exec(response)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-exec" for f in findings)

    def test_triggers_stream_var(self):
        code = 'exec(chunk)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-exec" for f in findings)

    def test_no_trigger_static(self):
        code = "exec(\"print('hello')\")\n"
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-output-to-exec" for f in findings)


class TestLlmOutputToSql:
    def test_triggers(self):
        code = 'cursor.execute(response)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-sql" for f in findings)

    def test_no_trigger_static(self):
        code = 'cursor.execute("SELECT 1")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-output-to-sql" for f in findings)


class TestLlmOutputToFile:
    def test_triggers(self):
        code = 'open(response)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-file" for f in findings)

    def test_no_trigger_static(self):
        code = 'open("config.json")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-output-to-file" for f in findings)


class TestLlmOutputToHtml:
    def test_triggers(self):
        code = 'render_template_string(response)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-html" for f in findings)

    def test_no_trigger_static(self):
        code = 'render_template_string("<h1>Hi</h1>")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-output-to-html" for f in findings)


class TestLlmOutputToImport:
    def test_triggers(self):
        code = 'importlib.import_module(response)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-import" for f in findings)

    def test_no_trigger_static(self):
        code = 'importlib.import_module("json")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-output-to-import" for f in findings)


class TestLlmOutputToPickle:
    def test_triggers(self):
        code = 'pickle.loads(response)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-output-to-pickle" for f in findings)

    def test_no_trigger_static(self):
        code = 'pickle.loads(b"safe_bytes")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-output-to-pickle" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  python.yaml — MCP tool rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLlmMcpToolShell:
    def test_triggers(self):
        code = '@mcp.tool()\ndef run_cmd(cmd: str):\n    subprocess.run(cmd, shell=True)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-mcp-tool-shell" for f in findings)

    def test_no_trigger_safe(self):
        code = '@mcp.tool()\ndef get_time():\n    return datetime.now()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-mcp-tool-shell" for f in findings)


class TestLlmMcpToolFileDelete:
    def test_triggers(self):
        code = '@server.tool()\ndef cleanup(path: str):\n    os.remove(path)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-mcp-tool-file-delete" for f in findings)

    def test_no_trigger_read_only(self):
        code = '@server.tool()\ndef read_file(path: str):\n    return Path(path).read_text()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-mcp-tool-file-delete" for f in findings)


class TestLlmNoRefusalCheck:
    def test_triggers(self):
        code = 'answer = resp.choices[0].message.content\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-no-refusal-check" for f in findings)

    def test_no_trigger_with_check_after(self):
        # refusal/finish_reason check must appear AFTER .content access (within 100 chars)
        code = 'answer = resp.choices[0].message.content if not resp.choices[0].message.refusal else None\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-no-refusal-check" for f in findings)


class TestLlmRagUnsanitizedIngest:
    def test_triggers(self):
        code = 'loader = SimpleDirectoryReader(upload_dir)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-rag-unsanitized-ingest" for f in findings)

    def test_no_trigger_curated(self):
        code = 'loader = SimpleDirectoryReader("./curated_docs/")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-rag-unsanitized-ingest" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  javascript.yaml — JS-specific LLM rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPromptInjectionOpenAITemplate:
    def test_triggers(self):
        code = 'openai.chat.completions.create({messages:[{content:`Hello ${userInput}`}]})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-openai-template" for f in findings)

    def test_no_trigger_static(self):
        code = 'openai.chat.completions.create({messages:[{content:"Hello"}]})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-openai-template" for f in findings)


class TestPromptInjectionVercelAI:
    def test_triggers(self):
        code = 'generateText({system:`You are ${persona}`})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-vercel-ai" for f in findings)

    def test_no_trigger_static(self):
        code = 'generateText({system:"You are a helper"})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-vercel-ai" for f in findings)


class TestPromptInjectionAnthropicJs:
    def test_triggers(self):
        code = 'anthropic.messages.create({messages:[{content:`${userMsg}`}]})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-anthropic-js" for f in findings)

    def test_no_trigger_static(self):
        code = 'anthropic.messages.create({messages:[{content:"safe"}]})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-anthropic-js" for f in findings)


class TestPromptInjectionLangchainJs:
    def test_triggers(self):
        code = 'ChatPromptTemplate.fromTemplate(`Answer ${q}`)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-langchain-js" for f in findings)

    def test_no_trigger_static(self):
        code = 'ChatPromptTemplate.fromTemplate("Answer the question")\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-langchain-js" for f in findings)


class TestLlmOutputToEvalJs:
    def test_triggers(self):
        code = 'eval(response)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-output-to-eval-js" for f in findings)

    def test_triggers_stream_var(self):
        code = 'eval(delta)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-output-to-eval-js" for f in findings)

    def test_no_trigger_static(self):
        code = 'eval("1+1")\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-output-to-eval-js" for f in findings)


class TestLlmOutputToInnerhtml:
    def test_triggers(self):
        code = 'el.innerHTML = response\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-output-to-innerhtml" for f in findings)

    def test_no_trigger_static(self):
        code = 'el.innerHTML = "safe"\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-output-to-innerhtml" for f in findings)


class TestLlmOutputToSqlJs:
    def test_triggers(self):
        code = 'db.query(generated)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-output-to-sql-js" for f in findings)

    def test_no_trigger_static(self):
        code = 'db.query("SELECT 1")\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-output-to-sql-js" for f in findings)


class TestLlmOutputToRedirect:
    def test_triggers(self):
        code = 'res.redirect(response)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-output-to-redirect" for f in findings)

    def test_no_trigger_static(self):
        code = 'res.redirect("/dashboard")\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-output-to-redirect" for f in findings)


class TestLlmOutputToFs:
    def test_triggers(self):
        code = 'fs.writeFile(generated, data)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-output-to-fs" for f in findings)

    def test_no_trigger_static(self):
        code = 'fs.writeFile("out.txt", data)\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-output-to-fs" for f in findings)


class TestLlmMcpToolExecJs:
    def test_triggers(self):
        code = 'server.tool("run", async (args) => {\n  exec(args.command)\n})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-mcp-tool-exec-js" for f in findings)

    def test_no_trigger_safe(self):
        code = 'server.tool("greet", async (args) => {\n  return "hello"\n})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-mcp-tool-exec-js" for f in findings)


class TestLlmClientMessagesDirectJs:
    def test_triggers(self):
        code = 'const msgs = req.body.messages\nopenai.chat.completions.create({messages: msgs})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-client-messages-direct" for f in findings)

    def test_no_trigger_wrapped(self):
        code = 'const msg = req.body.input\nconst msgs = [{role:"user", content: msg}]\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "llm-client-messages-direct" for f in findings)
