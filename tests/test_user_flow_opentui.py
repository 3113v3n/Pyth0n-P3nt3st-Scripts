from handlers.user_flow_mixin import UserFlowMixin


class _FlowHarness(UserFlowMixin):
    HEADER = ""
    ENDC = ""
    WARNING = ""
    OKGREEN = ""
    output_directory = "/tmp/output"
    vulnerability_scanners = [
        {"name": "Nessus Scanner", "alias": "nessus"},
        {"name": "Rapid7 Scanner", "alias": "rapid"},
    ]
    SCAN_FILE_FORMAT = ["csv", "xlsx", "both"]

    def __init__(self):
        self._state = {}
        self.domain_variables = None
        self.files = []
        self.debug = False
        self.helper_ = type(
            "Helper",
            (),
            {
                "mobile_helper": staticmethod(lambda: None),
                "vulnerability_helper": staticmethod(lambda: None),
                "external_helper": staticmethod(lambda: None),
                "internal_helper": staticmethod(lambda *args, **kwargs: None),
            },
        )()

    def _get_menu_state(self, module):
        return self._state.setdefault(module, {})

    def _clear_all_menu_state(self):
        self._state = {}

    def _go_to_previous_step(self, step):
        return max(0, step - 1)

    def start_domain_helper(self, helper_function, **kwargs):
        return None

    def prompt_format(self, prompt, **kwargs):
        raise AssertionError(f"unexpected prompt_format call: {prompt}")

    def prompt_for_multi_choice(self, **kwargs):
        if kwargs.get("title") == "External":
            return ("recon", "urls")
        raise AssertionError(f"unexpected prompt_for_multi_choice call: {kwargs}")

    def prompt_for_choice(self, **kwargs):
        raise AssertionError(f"unexpected prompt_for_choice call: {kwargs}")

    def get_file_path(self, prompt, check_exists, **kwargs):
        return "/tmp/apps"

    def find_files(self, search_path):
        return []

    def _get_file_collections(self):
        return {
            "applications": [
                {"filename": "one.apk", "full_path": "/tmp/apps/one.apk"},
                {"filename": "two.apk", "full_path": "/tmp/apps/two.apk"},
            ]
        }

    def print_info_message(self, *args, **kwargs):
        return None

    def print_warning_message(self, *args, **kwargs):
        return None

    def print_error_message(self, *args, **kwargs):
        raise AssertionError(f"unexpected error: {args} {kwargs}")

    def _display_file_options(self):
        return None

    def index_out_of_range_display(self, prompt, data_list):
        return 1

    def create_menu_selection(self, **kwargs):
        return 0

    def display_files_onscreen(self, *args, **kwargs):
        return ([{"filename": "report.csv", "full_path": "/tmp/report.csv"}], 0)

    def get_output_filename(self, prompt=""):
        return "report"

    def validate_domain(self, domain):
        return True

    def get_user_input(self, prompt, default=None):
        if default is not None:
            return default
        return "example.com"


def test_mobile_ui_handler_uses_prompt_for_choice_for_taxonomy_profile_and_scan_mode(monkeypatch):
    handler = _FlowHarness()
    prompts = []
    responses = iter(["mastg", "aggressive", "all"])

    def fake_prompt_for_choice(**kwargs):
        prompts.append((kwargs["title"], kwargs["prompt"]))
        return next(responses)

    monkeypatch.setattr(handler, "prompt_for_choice", fake_prompt_for_choice)

    result = handler.mobile_ui_handler()

    assert result["scan_mode"] == "all"
    assert result["taxonomy"] == "mastg"
    assert result["taxonomy_profile"] == "aggressive"
    assert [title for title, _prompt in prompts] == ["Mobile", "Mobile", "Mobile"]


def test_va_ui_handler_uses_prompt_for_choice_for_credentialed_check(monkeypatch):
    handler = _FlowHarness()
    prompts = []

    def fake_prompt_for_choice(**kwargs):
        prompts.append(kwargs)
        return "no"

    monkeypatch.setattr(handler, "prompt_for_choice", fake_prompt_for_choice)

    result = handler.va_ui_handler()

    assert result["scanner"] == "nessus"
    assert result["credentialed_check"] is False
    assert any("credentialed" in prompt["prompt"].lower() for prompt in prompts)


def test_external_ui_handler_uses_prompt_for_choice_for_safe_mode(monkeypatch):
    handler = _FlowHarness()
    prompts = []

    def fake_prompt_for_choice(**kwargs):
        prompts.append(kwargs)
        return "no"

    monkeypatch.setattr(handler, "prompt_for_choice", fake_prompt_for_choice)

    result = handler.external_ui_handler()

    assert result["safe_mode"] is False
    assert result["operator_tag"] == ""
    assert result["phases"] == ("recon", "urls")
    assert any("safe mode" in prompt["prompt"].lower() for prompt in prompts)
