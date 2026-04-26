"""Domain assessment orchestration methods for PentestFramework."""

from __future__ import annotations


class FrameworkAssessmentMixin:
    """Dispatch and run the selected assessment domain."""

    def handle_internal_assessment(self, user, network, internal, **kwargs):
        """Handle Internal penetration testing assessment."""
        from utils.shared.progress_bar import ProgressBar

        _vars = {}
        _action = ""
        _output_file = ""

        if not kwargs.get("user_data"):
            _vars = user.domain_variables
            test_domain = user.domain
            _action = _vars["action"]
            _output_file = _vars["output"]

            if _action == "resume":
                network.existing_unresponsive_ips = user.existing_unresponsive_ips
        else:
            _vars = kwargs.get("user_data")
            test_domain = _vars["module"]
            _action = _vars["action"]

            if _action == "resume":
                resume_file = _vars["resume_file"]
                subnet_mask = _vars["mask"]
                last_ip = user.get_last_unresponsive_ip(resume_file)
                # Resume flow now rebuilds subnet context from the persisted host file.
                _vars["subnet"] = f"{last_ip}/{subnet_mask}"
                _output_file = resume_file
            elif _action == "scan":
                _output_file = _vars["output"]
                network.existing_unresponsive_ips = user.existing_unresponsive_ips

        network.initialize_network_variables(_vars, test_domain, ProgressBar)
        internal.initialize_variables(
            is_cmdl=self.cmd_args,
            mode=_action,
            output_file=_output_file,
        )
        internal.enumerate_hosts()

    @staticmethod
    def handle_password_operations(user, password, **kwargs):
        """Handle Password related operations."""
        output_dir = user.output_directory
        generator_func = user.generate_unique_name

        if kwargs.get("user_data"):
            variables = kwargs.get("user_data")
            selected_action = variables.get("action")
        else:
            variables = user.domain_variables
            selected_action = variables["action"]

        module_handler = {
            "generate": lambda: password.generate_password_list_from_hashes(
                variables,
                output_dir,
                generator_func,
            ),
            "test": lambda: password.test_valid_passwords(
                variables,
                generator_func,
                output_dir,
            ),
        }
        run_action = module_handler.get(selected_action)
        if run_action:
            run_action()

    def handle_vulnerability_assessment(self, user: callable, vulnerability_analysis: callable, **kwargs):
        """Handle Vulnerability analysis."""
        try:
            scanner_type = "nessus"

            if kwargs.get("user_data"):
                _vars = kwargs.get("user_data")
                test_domain: str = _vars["module"]
                output_file: str = _vars["output_file"]
                all_files = _vars["scan_files"]

                if not all_files:
                    raise ValueError("No files found in the specified scan folder")
                input_files: tuple = all_files, 0
            else:
                scanner_type = user.domain_variables.get("scanner")
                input_files = user.domain_variables.get("input_file")
                test_domain = user.domain
                output_file = user.domain_variables.get("output")

            vulnerability_analysis.set_scanner(scanner_type)
            vulnerability_analysis.analyze_scan_files(
                test_domain,
                input_files,
                output_file,
            )
            vulnerability_analysis.decorator.print_total_time(
                "Analysis Completed in Approximately: "
            )
            return True
        except Exception as error:
            self.print_error_message(
                message="Error in vulnerability assessment",
                exception_error=error,
            )
            return False
        finally:
            vulnerability_analysis.decorator.reset_total_time()

    def handle_mobile_assessment(self, user, mobile, **kwargs):
        """Handle mobile application assessment."""
        if kwargs.get("user_data"):
            mobile_testing_vars = kwargs["user_data"]
            test_domain = mobile_testing_vars.get("module")
        else:
            mobile_testing_vars = user.domain_variables
            test_domain = user.domain

        applications = (
            mobile_testing_vars.get("applications")
            if isinstance(mobile_testing_vars, dict)
            else None
        )

        mobile.reset_total_time()
        if applications:
            total = len(applications)
            self.print_info_message(f"Running mobile assessment on {total} application(s)")
            for index, app in enumerate(applications, 1):
                filename = app.get("filename", "unknown")
                self.print_info_message(
                    message=f"Scanning application [{index}/{total}]",
                    file=filename,
                )
                app_vars = {
                    "filename": filename,
                    "full_path": app.get("full_path"),
                }
                mobile.initialize_variables(app_vars)
                mobile._inspect_files(test_domain, self.os)
            mobile.print_total_time("Total analysis time for all applications:")
            mobile.reset_total_time()
            return

        mobile.initialize_variables(mobile_testing_vars)
        mobile._inspect_files(test_domain, self.os)
        mobile.print_total_time(f"Total analysis time for {mobile.package_name}:")
        mobile.reset_total_time()

    def handle_external_assessment(self, user, external, **kwargs):
        """Handle external penetration testing assessment."""
        from pathlib import Path

        if kwargs.get("user_data"):
            variables = kwargs["user_data"]
            target_domain = variables.get("target_domain")
            phases = variables.get("phases")
        else:
            variables = user.domain_variables or {}
            target_domain = variables.get("target_domain")
            phases = variables.get("phases")

        if not target_domain:
            self.print_error_message("No target domain provided for external assessment")
            return

        # Output directory was created by user.update_output_directory("external").
        base_dir = Path(user.output_directory) / "External"
        base_dir.mkdir(parents=True, exist_ok=True)

        external.initialize_variables({
            "target_domain": target_domain,
            "phases": phases,
            "base_dir": base_dir,
        })
        external.decorator.reset_total_time()
        try:
            external.run()
        finally:
            external.decorator.reset_total_time()

    def process_domain(self, user_test_domain: str, **kwargs) -> None:
        """Process the selected testing domain."""
        user_data = kwargs.get("user_data")
        if self.debug:
            self.print_debug_message(f"Commandline Arguments {user_data}")

        # Kept as explicit branches to preserve existing per-domain side effects.
        if user_test_domain == "internal":
            internal = self._load_domain("internal")
            if internal is None:
                return
            self.handle_internal_assessment(
                self.classes["user"],
                self.classes["network"],
                internal,
                user_data=user_data,
            )
            return

        if user_test_domain == "va":
            vulnerability = self._load_domain("vulnerability")
            if vulnerability is None:
                return
            self.handle_vulnerability_assessment(
                self.classes["user"],
                vulnerability,
                user_data=user_data,
            )
            return

        if user_test_domain == "mobile":
            mobile = self._load_domain("mobile")
            if mobile is None:
                return
            self.handle_mobile_assessment(
                self.classes["user"],
                mobile,
                user_data=user_data,
            )
            return

        if user_test_domain == "external":
            external = self._load_domain("external")
            if external is None:
                return
            self.handle_external_assessment(
                self.classes["user"],
                external,
                user_data=user_data,
            )
            return

        if user_test_domain == "password":
            password = self._load_domain("password")
            if password is None:
                return
            self.handle_password_operations(
                self.classes["user"],
                password,
                user_data=user_data,
            )
            return

        self.print_error_message("Invalid test domain selected")
