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

    def test_no_trigger_static(self):
        code = 'system_prompt = "You are a helper"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-fstring" for f in findings)


class TestPromptInjectionFormat:
    def test_triggers_python(self):
        code = 'prompt = "Help {}".format(topic)\n'
        findings = run_regex_checks(code, "app.py", "python")
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
    def test_triggers_2_0(self):
        code = 'temperature=2.0,\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-temperature-max" for f in findings)

    def test_triggers_1_5(self):
        code = 'temperature=1.5,\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-temperature-max" for f in findings)

    def test_triggers_1_9(self):
        code = 'temperature=1.9,\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-temperature-max" for f in findings)

    def test_no_trigger_0_7(self):
        code = 'temperature=0.7,\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-temperature-max" for f in findings)

    def test_no_trigger_1_0(self):
        code = 'temperature=1.0,\n'
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Fold 49 — Additional SDK, multimodal, OWASP LLM02
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPromptInjectionOllama:
    def test_triggers(self):
        code = 'ollama.chat(model="llama3", messages=[{"content": f"Help {user}"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-ollama" for f in findings)

    def test_no_trigger_static(self):
        code = 'ollama.chat(model="llama3", messages=[{"content": "Hello"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-ollama" for f in findings)


class TestPromptInjectionBedrock:
    def test_triggers(self):
        code = 'client.invoke_model(body=json.dumps({"prompt": f"Tell me about {topic}"}))\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-bedrock" for f in findings)

    def test_no_trigger_static(self):
        code = 'client.invoke_model(body=json.dumps({"prompt": "Hello"}))\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-bedrock" for f in findings)


class TestPromptInjectionGroq:
    def test_triggers(self):
        code = 'groq.chat.completions.create(messages=[{"content": f"Do {task}"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-groq" for f in findings)

    def test_no_trigger_static(self):
        code = 'groq.chat.completions.create(messages=[{"content": "Hello"}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-groq" for f in findings)


class TestLlmUntrustedImageToVision:
    def test_triggers(self):
        code = 'image_url = request.files["image"]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-untrusted-image-to-vision" for f in findings)

    def test_no_trigger_static(self):
        code = 'image_url = "https://example.com/static.png"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-untrusted-image-to-vision" for f in findings)


class TestLlmBase64ImageFromInput:
    def test_triggers(self):
        code = 'encoded = base64.b64encode(request.files["image"].read())\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-base64-image-from-input" for f in findings)

    def test_no_trigger_static(self):
        code = 'encoded = base64.b64encode(static_image_bytes)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-base64-image-from-input" for f in findings)


class TestLlmResponseNoPiiFilter:
    def test_triggers(self):
        code = 'return jsonify(response.content)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-response-no-pii-filter" for f in findings)

    def test_no_trigger_different_var(self):
        code = 'return jsonify({"status": "ok"})\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-response-no-pii-filter" for f in findings)


class TestSeverityCalibration:
    """Generic prompt concat rules should be warning, not critical."""

    def test_fstring_is_warning(self):
        code = 'system_prompt = f"You are {persona}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        match = [f for f in findings if f.rule == "prompt-injection-fstring"]
        assert match and match[0].severity.name.lower() == "warning"

    def test_content_fstring_is_critical(self):
        code = '"content": f"Hello {user}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        match = [f for f in findings if f.rule == "prompt-injection-content-fstring"]
        assert match and match[0].severity.name.lower() == "critical"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Missing rule coverage + OWASP LLM04/LLM10
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPromptInjectionJinjaPrompt:
    def test_triggers(self):
        code = 'template = jinja2.Template(prompt_template)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-jinja-prompt" for f in findings)

    def test_no_trigger_literal(self):
        code = 'template = jinja2.Template("Hello {{ name }}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-jinja-prompt" for f in findings)


class TestPromptInjectionRequestToLlm:
    def test_triggers(self):
        code = 'user_msg = request.json["input"]\nchat.completions.create(messages=[{"content": user_msg}])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-request-to-llm" for f in findings)

    def test_no_trigger_no_llm(self):
        code = 'user_msg = request.json["input"]\ndb.save(user_msg)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-request-to-llm" for f in findings)


class TestPromptInjectionEmailToPrompt:
    def test_triggers(self):
        code = 'body = email.get_payload()\nprompt = body\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-email-to-prompt" for f in findings)

    def test_no_trigger_no_prompt(self):
        code = 'body = email.get_payload()\narchive = body\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-email-to-prompt" for f in findings)


class TestPromptInjectionScrapeToPrompt:
    def test_triggers(self):
        code = 'text = BeautifulSoup(html).get_text()\nprompt += text\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "prompt-injection-scrape-to-prompt" for f in findings)

    def test_no_trigger_no_prompt(self):
        code = 'text = BeautifulSoup(html).get_text()\nresult = process(text)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "prompt-injection-scrape-to-prompt" for f in findings)


class TestPromptInjectionOpenaiConcatJs:
    def test_triggers(self):
        code = 'completions.create({messages:[{content: "Hello " + userInput}]})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-openai-concat" for f in findings)

    def test_no_trigger_static(self):
        code = 'completions.create({messages:[{content: "Hello world"}]})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-openai-concat" for f in findings)


class TestPromptInjectionSystemContentJs:
    def test_triggers(self):
        code = '{role: \'system\', content: `You are ${role}`}\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-system-content-js" for f in findings)

    def test_no_trigger_static(self):
        code = '{role: \'system\', content: "You are a helper"}\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-system-content-js" for f in findings)


class TestPromptInjectionSystemContentConcat:
    def test_triggers(self):
        code = '{role: \'system\', content: "You are " + role}\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "prompt-injection-system-content-concat" for f in findings)

    def test_no_trigger_static(self):
        code = '{role: \'system\', content: "You are a helper"}\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert not any(f.rule == "prompt-injection-system-content-concat" for f in findings)


class TestLlmTrainingDataLeakCheck:
    def test_triggers(self):
        code = 'answer = response.content\nreturn send(answer)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-training-data-leak-check" for f in findings)

    def test_no_trigger_with_filter(self):
        code = 'answer = response.content\nfiltered = sanitize(answer)\nreturn send(filtered)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-training-data-leak-check" for f in findings)


class TestLlmUntrustedTrainingData:
    def test_triggers(self):
        code = 'dataset = load_dataset(request.form["data_path"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-untrusted-training-data" for f in findings)

    def test_no_trigger_static(self):
        code = 'dataset = load_dataset("imdb")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-untrusted-training-data" for f in findings)


class TestLlmFineTuneUntrusted:
    def test_triggers(self):
        code = 'trainer = Trainer(train_dataset=request.files["data"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-fine-tune-untrusted" for f in findings)

    def test_no_trigger_static(self):
        code = 'trainer = Trainer(train_dataset=curated_data)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-fine-tune-untrusted" for f in findings)


class TestLlmPickleModelLoad:
    def test_triggers(self):
        code = 'model = torch.load(request.files["model"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-pickle-model-load" for f in findings)

    def test_no_trigger_static(self):
        code = 'model = torch.load("model.pt")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-pickle-model-load" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Structured Output Manipulation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLlmJsonOutputToEval:
    def test_triggers_python(self):
        code = 'data = json.loads(response.text)\nresult = eval(data["code"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-eval" for f in findings)

    def test_triggers_completion(self):
        code = 'parsed = json.loads(completion.content)\nexec(parsed["script"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-eval" for f in findings)

    def test_no_trigger_static_json(self):
        code = 'data = json.loads(config_file.read())\nprint(data["key"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-json-output-to-eval" for f in findings)


class TestLlmJsonOutputToSql:
    def test_triggers_python(self):
        code = 'data = json.loads(response.text)\ncursor.execute(f"SELECT * FROM {data[\'table\']}")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-sql" for f in findings)

    def test_triggers_js(self):
        code = 'const data = JSON.parse(completion.body);\ndb.query("SELECT " + data.columns);\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-json-output-to-sql" for f in findings)

    def test_no_trigger_parameterized(self):
        code = 'data = json.loads(config.read())\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-json-output-to-sql" for f in findings)


class TestLlmJsonOutputToShell:
    def test_triggers_python(self):
        code = 'data = json.loads(response.text)\nsubprocess.run(data["command"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-shell" for f in findings)

    def test_triggers_js(self):
        code = 'const data = JSON.parse(llm.body);\nchild_process.exec(data.cmd);\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-json-output-to-shell" for f in findings)

    def test_no_trigger_static(self):
        code = 'data = json.loads(config.read())\nsubprocess.run(["ls", "-la"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-json-output-to-shell" for f in findings)


class TestLlmJsonOutputToUrl:
    def test_triggers_python(self):
        code = 'data = json.loads(response.text)\nrequests.get(data["url"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-url" for f in findings)

    def test_triggers_js(self):
        code = 'const data = JSON.parse(completion.body);\nfetch(data.endpoint);\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-json-output-to-url" for f in findings)

    def test_no_trigger_hardcoded(self):
        code = 'data = json.loads(config.read())\nrequests.get("https://api.example.com")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-json-output-to-url" for f in findings)


class TestLlmJsonOutputToTemplate:
    def test_triggers_python(self):
        code = 'data = json.loads(response.text)\nrender_template_string(data["template"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-template" for f in findings)

    def test_triggers_jinja(self):
        code = 'parsed = json.loads(llm_result.content)\ntemplate = Template(parsed["html"])\ntemplate.render()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-json-output-to-template" for f in findings)

    def test_no_trigger_static_template(self):
        code = 'data = json.loads(config.read())\nrender_template("index.html", name=data["name"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-json-output-to-template" for f in findings)


class TestLlmFunctionCallNoValidation:
    def test_triggers_getattr(self):
        code = 'function_name = response.function_call.name\nresult = getattr(module, function_name)(args)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-function-call-no-validation" for f in findings)

    def test_triggers_globals(self):
        code = 'tool_name = tool_calls[0].name\nfn = globals()[tool_name]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-function-call-no-validation" for f in findings)

    def test_no_trigger_allowlist(self):
        code = 'name = response.function_call.name\nif name in ALLOWED_FUNCTIONS:\n    result = ALLOWED_FUNCTIONS[name](args)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-function-call-no-validation" for f in findings)


class TestLlmStructuredOutputTrusted:
    def test_triggers_return(self):
        code = 'answer = response.choices[0].message.content\nreturn answer\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-structured-output-trusted" for f in findings)

    def test_triggers_json_response(self):
        code = 'text = completion.content\nres.json({"reply": text})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-structured-output-trusted" for f in findings)

    def test_no_trigger_sanitized(self):
        code = 'text = response.content\ncleaned = sanitize(text)\nreturn cleaned\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-structured-output-trusted" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  security.yaml — RAG-specific injection rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRagDocumentToPrompt:
    def test_triggers_langchain(self):
        code = 'docs = vectorstore.similarity_search(query)\nprompt = f"Context: {docs[0].page_content}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-document-to-prompt" for f in findings)

    def test_triggers_retriever(self):
        code = 'docs = retriever.get_relevant_documents(q)\nmessages.append({"content": docs[0]})\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-document-to-prompt" for f in findings)

    def test_no_trigger_sanitized(self):
        code = 'docs = vectorstore.similarity_search(query)\ncleaned = sanitize(docs)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "rag-document-to-prompt" for f in findings)


class TestRagMetadataInjection:
    def test_triggers(self):
        code = 'source = doc.metadata["source"]\nprompt += f"From {source}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-metadata-injection" for f in findings)

    def test_no_trigger_no_prompt(self):
        code = 'source = doc.metadata["source"]\nlog.info(source)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "rag-metadata-injection" for f in findings)


class TestRagNoChunkSanitization:
    def test_triggers_join(self):
        code = 'context = "\\n".join(chunks)\nprompt = f"Context: {context}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-no-chunk-sanitization" for f in findings)

    def test_no_trigger_filtered(self):
        code = 'context = "\\n".join(chunks)\ndb.save(context)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "rag-no-chunk-sanitization" for f in findings)


class TestRagUserQueryInSystemPrompt:
    def test_triggers(self):
        code = '{"role": "system", "content": f"Answer the query: {user_query}"}\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-user-query-in-system-prompt" for f in findings)

    def test_no_trigger_user_role(self):
        code = '{"role": "user", "content": user_query}\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "rag-user-query-in-system-prompt" for f in findings)


class TestRagUnboundedContext:
    def test_triggers(self):
        code = 'for doc in results:\n    prompt += doc.page_content\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-unbounded-context" for f in findings)

    def test_no_trigger_sliced(self):
        code = 'for doc in results[:5]:\n    prompt += doc.page_content\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "rag-unbounded-context" for f in findings)


class TestRagSourceTrustBoundary:
    def test_triggers_upload(self):
        code = 'vectorstore.add_documents(request.files["docs"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-source-trust-boundary" for f in findings)

    def test_triggers_user_file(self):
        code = 'index.upsert(vectors=uploaded_chunks)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "rag-source-trust-boundary" for f in findings)

    def test_no_trigger_curated(self):
        code = 'vectorstore.add_documents(curated_docs)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "rag-source-trust-boundary" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  C# LLM security rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCsharpPromptInjectionInterpolation:
    def test_triggers(self):
        code = 'var prompt = $"You are a {role} assistant";\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert any(f.rule == "csharp-prompt-injection-interpolation" for f in findings)

    def test_no_trigger_static(self):
        code = 'var prompt = "You are a helpful assistant";\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert not any(f.rule == "csharp-prompt-injection-interpolation" for f in findings)


class TestCsharpPromptInjectionSystemRole:
    def test_triggers(self):
        code = 'new ChatMessage(ChatRole.System, $"You are {persona}");\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert any(f.rule == "csharp-prompt-injection-system-role" for f in findings)

    def test_no_trigger_static(self):
        code = 'new ChatMessage(ChatRole.System, "You are a helpful bot");\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert not any(f.rule == "csharp-prompt-injection-system-role" for f in findings)


class TestCsharpSemanticKernelPromptInjection:
    def test_triggers(self):
        code = 'var func = kernel.CreateFunctionFromPrompt($"Summarize {userInput}");\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert any(f.rule == "csharp-semantic-kernel-prompt-injection" for f in findings)

    def test_no_trigger_static(self):
        code = 'var func = kernel.CreateFunctionFromPrompt("Summarize the text");\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert not any(f.rule == "csharp-semantic-kernel-prompt-injection" for f in findings)


class TestCsharpLlmToolCallToProcess:
    def test_triggers(self):
        code = 'var cmd = toolResult.content;\nProcess.Start(cmd);\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert any(f.rule == "csharp-llm-tool-call-to-process" for f in findings)

    def test_no_trigger_static(self):
        code = 'Process.Start("notepad.exe");\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert not any(f.rule == "csharp-llm-tool-call-to-process" for f in findings)


class TestCsharpLlmNoContentFilter:
    def test_triggers(self):
        code = 'var client = new OpenAIClient(apiKey);\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert any(f.rule == "csharp-llm-no-content-filter" for f in findings)

    def test_no_trigger_with_filter(self):
        code = 'var opts = new ChatCompletionsOptions(ContentFilter.Default);\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert not any(f.rule == "csharp-llm-no-content-filter" for f in findings)


class TestCsharpLlmSecretInPrompt:
    def test_triggers(self):
        code = 'var prompt = $"Connect using {connectionString} to db";\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert any(f.rule == "csharp-llm-secret-in-prompt" for f in findings)

    def test_no_trigger_safe(self):
        code = 'var prompt = $"Hello {userName}, how can I help?";\n'
        findings = run_regex_checks(code, "app.cs", "csharp")
        assert not any(f.rule == "csharp-llm-secret-in-prompt" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PHP LLM security rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPhpPromptInjectionInterpolation:
    def test_triggers(self):
        code = '$prompt = "You are a $role assistant";\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert any(f.rule == "php-prompt-injection-interpolation" for f in findings)

    def test_no_trigger_static(self):
        code = "$prompt = 'You are a helpful assistant';\n"
        findings = run_regex_checks(code, "app.php", "php")
        assert not any(f.rule == "php-prompt-injection-interpolation" for f in findings)


class TestPhpPromptInjectionSystemRole:
    def test_triggers(self):
        code = '["role" => "system", "content" => "You are $persona"];\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert any(f.rule == "php-prompt-injection-system-role" for f in findings)

    def test_no_trigger_static(self):
        code = "[\"role\" => \"system\", \"content\" => \"You are a bot\"];\n"
        findings = run_regex_checks(code, "app.php", "php")
        assert not any(f.rule == "php-prompt-injection-system-role" for f in findings)


class TestPhpLlmToolCallToExec:
    def test_triggers(self):
        code = '$cmd = $tool_result->content;\nexec($cmd);\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert any(f.rule == "php-llm-tool-call-to-exec" for f in findings)

    def test_no_trigger_static(self):
        code = 'exec("ls -la");\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert not any(f.rule == "php-llm-tool-call-to-exec" for f in findings)


class TestPhpLlmResponseToEval:
    def test_triggers(self):
        code = '$code = $response->content;\neval($code);\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert any(f.rule == "php-llm-response-to-eval" for f in findings)

    def test_no_trigger_static(self):
        code = '$x = $response->content;\necho $x;\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert not any(f.rule == "php-llm-response-to-eval" for f in findings)


class TestPhpLlmNoInputValidation:
    def test_triggers(self):
        code = '$prompt = "Tell me about " . $_GET["topic"];\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert any(f.rule == "php-llm-no-input-validation" for f in findings)

    def test_no_trigger_sanitized(self):
        code = '$topic = htmlspecialchars($_GET["topic"]);\n$prompt = "Tell me about " . $topic;\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert not any(f.rule == "php-llm-no-input-validation" for f in findings)


class TestPhpLlmSecretInPrompt:
    def test_triggers(self):
        code = '$prompt = "Use key $api_key to connect";\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert any(f.rule == "php-llm-secret-in-prompt" for f in findings)

    def test_no_trigger_safe(self):
        code = '$prompt = "Hello $username, welcome";\n'
        findings = run_regex_checks(code, "app.php", "php")
        assert not any(f.rule == "php-llm-secret-in-prompt" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Rust LLM security rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRustPromptInjectionFormat:
    def test_triggers(self):
        code = 'let prompt = format!("You are a {role} assistant");\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert any(f.rule == "rust-prompt-injection-format" for f in findings)

    def test_no_trigger_static(self):
        code = 'let prompt = "You are a helpful assistant";\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert not any(f.rule == "rust-prompt-injection-format" for f in findings)


class TestRustPromptInjectionSystemRole:
    def test_triggers(self):
        code = 'let system_msg = format!("You are {persona}");\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert any(f.rule == "rust-prompt-injection-system-role" for f in findings)

    def test_no_trigger_static(self):
        code = 'let system_msg = "You are a helpful bot";\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert not any(f.rule == "rust-prompt-injection-system-role" for f in findings)


class TestRustLlmUnsafeDeserialize:
    def test_triggers(self):
        code = 'let data = response_content;\nlet action: Action = serde_json::from_str(&data).unwrap();\naction.command.exec();\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert any(f.rule == "rust-llm-unsafe-deserialize" for f in findings)

    def test_no_trigger_safe(self):
        code = 'let config: Config = serde_json::from_str(&file_data).unwrap();\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert not any(f.rule == "rust-llm-unsafe-deserialize" for f in findings)


class TestRustLlmToolCallToCommand:
    def test_triggers(self):
        code = 'let cmd = tool_result.content;\nCommand::new(cmd).spawn();\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert any(f.rule == "rust-llm-tool-call-to-command" for f in findings)

    def test_no_trigger_static(self):
        code = 'Command::new("ls").arg("-la").spawn();\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert not any(f.rule == "rust-llm-tool-call-to-command" for f in findings)


class TestRustLlmModelUnsafeLoad:
    def test_triggers(self):
        code = 'let path = user_input;\nunsafe { model.load(&path); }\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert any(f.rule == "rust-llm-model-unsafe-load" for f in findings)

    def test_no_trigger_safe(self):
        code = 'let model = Model::from_file("weights.bin");\n'
        findings = run_regex_checks(code, "app.rs", "rust")
        assert not any(f.rule == "rust-llm-model-unsafe-load" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  security.yaml — AI Agent Framework rules (CrewAI, AutoGen, DSPy, LangGraph, Claude SDK)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCrewaiAgentAllowCodeExecution:
    def test_triggers(self):
        code = 'agent = Agent(\n    role="coder",\n    allow_code_execution=True\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "crewai-agent-allow-code-execution" for f in findings)

    def test_triggers_inline(self):
        code = 'Agent(role="dev", allow_code_execution=True, goal="code")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "crewai-agent-allow-code-execution" for f in findings)

    def test_no_trigger_false(self):
        code = 'Agent(role="researcher", allow_code_execution=False)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "crewai-agent-allow-code-execution" for f in findings)

    def test_no_trigger_no_flag(self):
        code = 'Agent(role="writer", goal="write articles")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "crewai-agent-allow-code-execution" for f in findings)


class TestCrewaiTaskUserInputInDescription:
    def test_triggers_fstring(self):
        code = 'Task(\n    description=f"Analyze {user_input}",\n    agent=researcher\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "crewai-task-user-input-in-description" for f in findings)

    def test_triggers_format(self):
        code = 'Task(description="Process {}".format(request.data))\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "crewai-task-user-input-in-description" for f in findings)

    def test_triggers_concat(self):
        code = 'Task(description="Handle " + user_query)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "crewai-task-user-input-in-description" for f in findings)

    def test_no_trigger_static(self):
        code = 'Task(description="Summarize the quarterly report", agent=analyst)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "crewai-task-user-input-in-description" for f in findings)


class TestCrewaiAgentDelegationUnrestricted:
    def test_triggers(self):
        code = 'Agent(\n    role="manager",\n    allow_delegation=True,\n    goal="coordinate"\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "crewai-agent-delegation-unrestricted" for f in findings)

    def test_no_trigger_false(self):
        code = 'Agent(role="worker", allow_delegation=False)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "crewai-agent-delegation-unrestricted" for f in findings)

    def test_no_trigger_no_flag(self):
        code = 'Agent(role="analyst", goal="analyze data")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "crewai-agent-delegation-unrestricted" for f in findings)


class TestAutogenCodeExecutorUnsafe:
    def test_triggers_local(self):
        code = 'executor = LocalCommandLineCodeExecutor(work_dir="coding")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "autogen-code-executor-unsafe" for f in findings)

    def test_triggers_docker(self):
        code = 'executor = DockerCommandLineCodeExecutor(image="python:3.11")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "autogen-code-executor-unsafe" for f in findings)

    def test_no_trigger_unrelated(self):
        code = 'executor = SafeCodeExecutor(sandbox=True)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "autogen-code-executor-unsafe" for f in findings)


class TestAutogenUserProxyAutoReply:
    def test_triggers(self):
        code = 'proxy = UserProxyAgent(\n    name="user",\n    human_input_mode="NEVER",\n    code_execution_config=config\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "autogen-user-proxy-auto-reply" for f in findings)

    def test_no_trigger_always(self):
        code = 'proxy = UserProxyAgent(name="user", human_input_mode="ALWAYS")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "autogen-user-proxy-auto-reply" for f in findings)

    def test_no_trigger_terminate(self):
        code = 'proxy = UserProxyAgent(name="user", human_input_mode="TERMINATE")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "autogen-user-proxy-auto-reply" for f in findings)


class TestAutogenRegisterFunctionUnvalidated:
    def test_triggers(self):
        code = 'register_function(\n    run_query,\n    caller=assistant,\n    executor=user_proxy,\n    description="Run a SQL query"\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "autogen-register-function-unvalidated" for f in findings)

    def test_no_trigger_no_caller(self):
        code = 'register_handler(my_func, event="on_message")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "autogen-register-function-unvalidated" for f in findings)


class TestDspyAssertBypass:
    def test_triggers(self):
        code = 'dspy.settings.configure(\n    lm=lm,\n    bypass_assert=True\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "dspy-assert-bypass" for f in findings)

    def test_triggers_configure(self):
        code = 'dspy.configure(lm=turbo, bypass_assert=True)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "dspy-assert-bypass" for f in findings)

    def test_no_trigger_false(self):
        code = 'dspy.settings.configure(lm=lm, bypass_assert=False)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "dspy-assert-bypass" for f in findings)

    def test_no_trigger_no_flag(self):
        code = 'dspy.settings.configure(lm=lm)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "dspy-assert-bypass" for f in findings)


class TestDspyToolUserInputUnsanitized:
    def test_triggers_request(self):
        code = 'tool = dspy.ReAct(\n    signature,\n    tools=[search],\n    query=request.args["q"]\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "dspy-tool-user-input-unsanitized" for f in findings)

    def test_triggers_user_input(self):
        code = 'predictor = dspy.Predict(sig, input=user_input)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "dspy-tool-user-input-unsanitized" for f in findings)

    def test_no_trigger_sanitized(self):
        code = 'predictor = dspy.Predict(sig, input=sanitized_data)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "dspy-tool-user-input-unsanitized" for f in findings)


class TestLanggraphToolNodeUnrestricted:
    def test_triggers_tools_var(self):
        code = 'tool_node = ToolNode(tools)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "langgraph-tool-node-unrestricted" for f in findings)

    def test_triggers_all_tools(self):
        code = 'tool_node = ToolNode(all_tools)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "langgraph-tool-node-unrestricted" for f in findings)

    def test_triggers_list(self):
        code = 'tool_node = ToolNode([search, calculator, shell_tool])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "langgraph-tool-node-unrestricted" for f in findings)

    def test_no_trigger_unrelated(self):
        code = 'node = GraphNode(name="processor")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "langgraph-tool-node-unrestricted" for f in findings)


class TestLanggraphHumanInLoopDisabled:
    def test_triggers(self):
        code = 'graph = StateGraph(AgentState)\ngraph.add_node("agent", call_model)\napp = graph.compile(checkpointer=memory)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "langgraph-human-in-loop-disabled" for f in findings)

    def test_triggers_no_checkpointer(self):
        code = 'graph = StateGraph(State)\ngraph.add_node("llm", run_llm)\napp = graph.compile()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "langgraph-human-in-loop-disabled" for f in findings)

    def test_no_trigger_with_interrupt(self):
        code = 'graph = StateGraph(State)\ngraph.add_node("agent", call_model)\napp = graph.compile(checkpointer=mem, interrupt_before=["tools"])\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "langgraph-human-in-loop-disabled" for f in findings)


class TestClaudeAgentSdkUnsafeTool:
    def test_triggers_exec(self):
        code = 'from claude_agent_sdk import Agent\nagent = Agent(tools=[my_tool])\nresult = exec(agent.output)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "claude-agent-sdk-unsafe-tool" for f in findings)

    def test_triggers_subprocess(self):
        code = 'import claude_code_sdk\nsubprocess.run(agent_response.command)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "claude-agent-sdk-unsafe-tool" for f in findings)

    def test_triggers_os_system(self):
        code = 'from anthropic.agent import Agent\nos.system(result.shell_cmd)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "claude-agent-sdk-unsafe-tool" for f in findings)

    def test_no_trigger_safe(self):
        code = 'from claude_agent_sdk import Agent\nagent = Agent(tools=[safe_search])\nprint(agent.output)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "claude-agent-sdk-unsafe-tool" for f in findings)


class TestClaudeAgentSdkNoGuardrails:
    def test_triggers(self):
        code = 'agent = Agent(\n    model="claude-3",\n    tools=[search, calculator],\n    max_turns=10\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "claude-agent-sdk-no-guardrails" for f in findings)

    def test_triggers_create_agent(self):
        code = 'agent = create_agent(\n    tools=[shell_tool, file_tool],\n    model="claude-3"\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "claude-agent-sdk-no-guardrails" for f in findings)

    def test_no_trigger_with_guardrails(self):
        code = 'agent = Agent(\n    model="claude-3",\n    tools=[search],\n    guardrail=safety_check\n)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "claude-agent-sdk-no-guardrails" for f in findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  security.yaml — encoding-based prompt injection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLlmBase64DecodeToPrompt:
    def test_triggers_python_b64decode(self):
        code = 'decoded = base64.b64decode(payload)\nprompt = f"Do this: {decoded}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-base64-decode-to-prompt" for f in findings)

    def test_triggers_js_atob(self):
        code = 'const decoded = atob(encoded);\nmessages.append({role: "user", content: decoded})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-base64-decode-to-prompt" for f in findings)

    def test_triggers_node_buffer(self):
        code = 'const text = Buffer.from(data, "base64").toString();\nprompt += text\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-base64-decode-to-prompt" for f in findings)

    def test_no_trigger_b64_for_image(self):
        code = 'image_data = base64.b64decode(img_str)\nwith open("out.png", "wb") as f:\n    f.write(image_data)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-base64-decode-to-prompt" for f in findings)

    def test_no_trigger_no_prompt(self):
        code = 'decoded = base64.b64decode(token)\nuser_id = decoded.split(b":")[0]\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-base64-decode-to-prompt" for f in findings)


class TestLlmRot13DecodeToPrompt:
    def test_triggers_codecs(self):
        code = 'hidden = codecs.decode(encoded, "rot13")\nprompt += hidden\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-rot13-decode-to-prompt" for f in findings)

    def test_triggers_maketrans(self):
        code = 'text = cipher.translate(str.maketrans(a, b))\nsystem_message = f"Instructions: {text}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-rot13-decode-to-prompt" for f in findings)

    def test_no_trigger_rot13_logging(self):
        code = 'obfuscated = codecs.decode(data, "rot13")\nlogger.debug(obfuscated)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-rot13-decode-to-prompt" for f in findings)


class TestLlmUnicodeEscapeInPrompt:
    def test_triggers_unicode_escape(self):
        code = 'prompt = "Hello \\u0048\\u0065\\u006c\\u0070 me"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-unicode-escape-in-prompt" for f in findings)

    def test_triggers_hex_escape(self):
        code = 'system_prompt = "Do \\x48\\x65\\x6c\\x70"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-unicode-escape-in-prompt" for f in findings)

    def test_triggers_unicode_escape_codec(self):
        code = 'instruction = data.decode("unicode_escape")\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-unicode-escape-in-prompt" for f in findings)

    def test_no_trigger_plain_prompt(self):
        code = 'prompt = "You are a helpful assistant"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-unicode-escape-in-prompt" for f in findings)


class TestLlmEncodedInstructionDecode:
    def test_triggers_zlib(self):
        code = 'text = zlib.decompress(payload)\nprompt = f"Execute: {text}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-encoded-instruction-decode" for f in findings)

    def test_triggers_gzip(self):
        code = 'data = gzip.decompress(blob)\nmessages.append({"role": "user", "content": data})\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-encoded-instruction-decode" for f in findings)

    def test_triggers_unhexlify(self):
        code = 'raw = binascii.unhexlify(hex_str)\nprompt += raw.decode()\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-encoded-instruction-decode" for f in findings)

    def test_no_trigger_decompress_to_file(self):
        code = 'data = zlib.decompress(blob)\nwith open("out.bin", "wb") as f:\n    f.write(data)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-encoded-instruction-decode" for f in findings)


class TestLlmPromptFromHex:
    def test_triggers_bytes_fromhex(self):
        code = 'payload = bytes.fromhex(hex_input)\nprompt = f"Run: {payload}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-prompt-from-hex" for f in findings)

    def test_triggers_buffer_hex(self):
        code = 'const text = Buffer.from(hexStr, "hex").toString();\nmessages.append({content: text})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-prompt-from-hex" for f in findings)

    def test_no_trigger_hex_for_hash(self):
        code = 'digest = bytes.fromhex(hash_value)\nassert digest == expected\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-prompt-from-hex" for f in findings)


class TestLlmMultilineAsciiArtInPrompt:
    def test_triggers_triple_quote(self):
        code = 'prompt = """\nline1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n"""\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-multiline-ascii-art-in-prompt" for f in findings)

    def test_triggers_template_literal(self):
        code = 'instruction = `\nline1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n`\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-multiline-ascii-art-in-prompt" for f in findings)

    def test_no_trigger_short_prompt(self):
        code = 'prompt = """You are a helpful assistant.\nBe concise."""\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-multiline-ascii-art-in-prompt" for f in findings)


class TestLlmPromptCharSubstitution:
    def test_triggers_chr_python(self):
        code = 'hidden = chr(72) + chr(101) + chr(108)\nprompt = f"Do: {hidden}"\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert any(f.rule == "llm-prompt-char-substitution" for f in findings)

    def test_triggers_fromcharcode_js(self):
        code = 'const cmd = String.fromCharCode(72, 101, 108);\nmessages.append({content: cmd})\n'
        findings = run_regex_checks(code, "app.js", "javascript")
        assert any(f.rule == "llm-prompt-char-substitution" for f in findings)

    def test_no_trigger_chr_no_prompt(self):
        code = 'separator = chr(0) + chr(10)\ndata = payload.split(separator)\n'
        findings = run_regex_checks(code, "app.py", "python")
        assert not any(f.rule == "llm-prompt-char-substitution" for f in findings)
