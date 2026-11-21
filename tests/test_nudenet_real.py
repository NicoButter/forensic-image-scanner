"""Opt-in real-runtime tests using generated images and an installed model root."""

from pathlib import Path

import pytest
from PIL import Image

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.detectors.nudenet import NUDENET_VARIANTS, NudeNetClient
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.model_paths import resolve_model_directory
from forensic_image_scanner.models.registry import ModelRegistry
from forensic_image_scanner.scoring.ensemble import FALCONSAI_MODEL, AnalysisProfile

pytestmark = pytest.mark.nudenet


@pytest.mark.parametrize("variant", NUDENET_VARIANTS)
def test_installed_backend_health_profiles_and_source_hash(tmp_path, variant):
    root = resolve_model_directory(None)
    installed = ModelRegistry(root).registered_model_ids()
    if f"nudenet-{variant}" not in installed:
        pytest.skip(f"NudeNet {variant} is not installed")
    source = tmp_path / "input"
    source.mkdir()
    image = source / "blánco con espacios.png"
    Image.new("RGB", (96, 96), "white").save(image)
    before = sha256_file(image)
    with NudeNetClient.from_registry(root, variant, source) as backend:
        assert backend.health["model"] == variant
        assert backend.health["license"] == "AGPL-3.0"
        assert backend.analyze(image).status == "OK"
        assert backend.analyze(Path(__file__).resolve()).status == "ERROR"

    profiles = [AnalysisProfile.NUDENET]
    if FALCONSAI_MODEL in installed:
        profiles.append(AnalysisProfile.COMBINED)
    for profile in profiles:
        summary = AnalysisService(root).run(
            AnalysisRequest(
                source,
                tmp_path / profile.value,
                FALCONSAI_MODEL,
                profile=profile,
                nudenet_variant=variant,
            )
        )
        result = summary.results[0]
        assert summary.errors == 0 and result.status == "completed"
        assert result.nudenet is not None and result.nudenet.status == "OK"
        assert result.triage is not None and result.triage_reasons
        assert (result.nsfw_score is None) == (profile is AnalysisProfile.NUDENET)
    assert before == sha256_file(image)
