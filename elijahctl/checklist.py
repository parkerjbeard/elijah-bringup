import json
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import asdict

from .config import Config, HitlChecklist, InsituChecklist, HealthCheckResult
from .utils.logging import get_logger, info, success, error, warning

logger = get_logger(__name__)


class ChecklistManager:
    def __init__(self):
        Config.init_directories()
        self.checklist_file = Config.INVENTORY_DIR / "checklist.csv"
        self.current_hitl = None
        self.current_insitu = None

    def load_hitl_checklist(self, data: Dict[str, Any]) -> HitlChecklist:
        self.current_hitl = HitlChecklist(
            serial_qr=data.get("serial_qr", ""),
            air_radio_fw_kept_factory=data.get("air_radio_fw_kept_factory", False),
            air_radio_configured=data.get("air_radio_configured", False),
            remoteid_configured=data.get("remoteid_configured", False),
            remoteid_serial_20d=data.get("remoteid_serial_20d", ""),
            remoteid_faa_entered=data.get("remoteid_faa_entered", False),
            jetson_git_hash=data.get("jetson_git_hash", ""),
            px4_fw_ref=data.get("px4_fw_ref", ""),
            param_set_version=data.get("param_set_version", ""),
            sysid_set=data.get("sysid_set", 0),
            seraph_hitl_ok=data.get("seraph_hitl_ok", False),
            esc_fw_ref=data.get("esc_fw_ref", ""),
            esc_params_ref=data.get("esc_params_ref", ""),
            motor_map_ok=data.get("motor_map_ok", False),
            ads_power_ok=data.get("ads_power_ok", False),
            arm_no_props_ok=data.get("arm_no_props_ok", False),
            arm_safety_param_ok=data.get("arm_safety_param_ok", False),
            elrs_configured=data.get("elrs_configured", None),
            hitl_signed_by=data.get("hitl_signed_by", ""),
            hitl_date=data.get("hitl_date", datetime.now().strftime("%Y-%m-%d")),
        )
        info("HITL checklist loaded")
        return self.current_hitl

    def load_insitu_checklist(self, data: Dict[str, Any]) -> InsituChecklist:
        self.current_insitu = InsituChecklist(
            installed_in_vehicle=data.get("installed_in_vehicle", False),
            seraph_insitu_ok=data.get("seraph_insitu_ok", False),
            insitu_signed_by=data.get("insitu_signed_by", ""),
            insitu_date=data.get("insitu_date", datetime.now().strftime("%Y-%m-%d")),
        )
        info("In-situ checklist loaded")
        return self.current_insitu

    def update_from_health_check(self, results: List[HealthCheckResult]):
        if not self.current_hitl:
            warning("No HITL checklist loaded")
            return

        for result in results:
            if result.component == "MAVLink" and result.status:
                info("MAVLink check passed - updating checklist")
            elif result.component == "Radio Stats" and result.status:
                info("Radio stats check passed - updating checklist")
            elif result.component == "PTH Sensors" and result.status:
                info("PTH sensors check passed - updating checklist")

        all_health_checks_passed = all(
            r.status
            for r in results
            if r.component in ["MAVLink", "Radio Stats", "PTH Sensors", "Video Stream"]
        )

        if all_health_checks_passed:
            self.current_hitl.seraph_hitl_ok = True
            success("All health checks passed - Seraph HITL marked OK")

    def save_run_record(self, drone_id: str, phase: str = "hitl") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_file = Config.RUNS_DIR / f"{timestamp}_{drone_id}_{phase}.json"

        run_data = {
            "timestamp": datetime.now().isoformat(),
            "drone_id": drone_id,
            "phase": phase,
            "hitl_checklist": self.current_hitl.to_dict() if self.current_hitl else None,
            "insitu_checklist": self.current_insitu.to_dict() if self.current_insitu else None,
            "hash": "",
        }

        content_str = json.dumps(run_data, sort_keys=True)
        run_data["hash"] = hashlib.sha256(content_str.encode()).hexdigest()[:16]

        with open(run_file, "w") as f:
            json.dump(run_data, f, indent=2)

        logger.debug(f"Run record saved to {run_file}")
        return str(run_file)

    def append_to_csv(self, drone_id: str):
        headers_exist = self.checklist_file.exists() and self.checklist_file.stat().st_size > 0

        with open(self.checklist_file, "a", newline="") as csvfile:
            fieldnames = [
                "drone_id",
                "serial_qr",
                "air_radio_fw_kept_factory",
                "air_radio_configured",
                "remoteid_configured",
                "remoteid_serial_20d",
                "remoteid_faa_entered",
                "jetson_git_hash",
                "px4_fw_ref",
                "param_set_version",
                "sysid_set",
                "seraph_hitl_ok",
                "esc_fw_ref",
                "esc_params_ref",
                "motor_map_ok",
                "ads_power_ok",
                "arm_no_props_ok",
                "arm_safety_param_ok",
                "elrs_configured",
                "hitl_signed_by",
                "hitl_date",
                "installed_in_vehicle",
                "seraph_insitu_ok",
                "insitu_signed_by",
                "insitu_date",
                "timestamp",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            if not headers_exist:
                writer.writeheader()

            row_data = {"drone_id": drone_id, "timestamp": datetime.now().isoformat()}

            if self.current_hitl:
                row_data.update(self.current_hitl.to_dict())

            if self.current_insitu:
                row_data.update(self.current_insitu.to_dict())

            writer.writerow(row_data)

        success(f"Checklist appended to {self.checklist_file}")

    def validate_completeness(self, phase: str = "hitl") -> Tuple[bool, List[str]]:
        missing_fields = []

        if phase == "hitl" and self.current_hitl:
            checklist = self.current_hitl.to_dict()
            required_fields = [
                "serial_qr",
                "remoteid_serial_20d",
                "jetson_git_hash",
                "px4_fw_ref",
                "param_set_version",
                "sysid_set",
                "esc_fw_ref",
                "esc_params_ref",
                "hitl_signed_by",
            ]

            for field in required_fields:
                value = checklist.get(field)
                if not value or (isinstance(value, str) and not value.strip()):
                    missing_fields.append(field)

            boolean_fields = [
                "air_radio_fw_kept_factory",
                "air_radio_configured",
                "remoteid_configured",
                "remoteid_faa_entered",
                "seraph_hitl_ok",
                "motor_map_ok",
                "ads_power_ok",
                "arm_no_props_ok",
                "arm_safety_param_ok",
            ]

            for field in boolean_fields:
                if not checklist.get(field):
                    missing_fields.append(field)

        elif phase == "insitu" and self.current_insitu:
            checklist = self.current_insitu.to_dict()

            if not checklist.get("installed_in_vehicle"):
                missing_fields.append("installed_in_vehicle")
            if not checklist.get("seraph_insitu_ok"):
                missing_fields.append("seraph_insitu_ok")
            if not checklist.get("insitu_signed_by"):
                missing_fields.append("insitu_signed_by")

        is_complete = len(missing_fields) == 0

        if is_complete:
            success(f"{phase.upper()} checklist is complete")
        else:
            warning(f"{phase.upper()} checklist incomplete. Missing: {', '.join(missing_fields)}")

        return is_complete, missing_fields

    def load_from_file(self, filepath: str) -> bool:
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            if "hitl_checklist" in data:
                self.load_hitl_checklist(data["hitl_checklist"])

            if "insitu_checklist" in data:
                self.load_insitu_checklist(data["insitu_checklist"])

            success(f"Checklist loaded from {filepath}")
            return True

        except Exception as e:
            error(f"Failed to load checklist: {e}")
            return False

    def generate_labels(self, drone_id: str) -> Dict[str, str]:
        labels = {
            "jetson": f"el-{drone_id}",
            "radio": f"{drone_id}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }

        if self.current_hitl:
            labels["serial"] = (
                self.current_hitl.serial_qr[:10] if self.current_hitl.serial_qr else "N/A"
            )
            labels["sysid"] = str(self.current_hitl.sysid_set)

        info(f"Generated labels for drone {drone_id}")
        return labels
