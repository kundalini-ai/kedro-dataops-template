
from typing import Dict
from kedro.pipeline import Pipeline
from .pipelines._00_gcp_creds_create import pipeline as _00_gcp_creds_create
from .pipelines._00_gcp_creds_delete import pipeline as _00_gcp_creds_delete

def register_pipelines() -> Dict[str, Pipeline]:
    """Register the project's pipeline.

    Returns:
        A mapping from a pipeline name to a ``Pipeline`` object.

    """
    creds_create = _00_gcp_creds_create.create_pipeline()
    creds_delete = _00_gcp_creds_delete.create_pipeline()

    return {
        "__default__": creds_create + creds_delete,
        "creds_create": creds_create,
        "creds_delete": creds_delete,
    }