from kedro.pipeline import Pipeline, node
from kedro.pipeline.modular_pipeline import pipeline
from .nodes import gcp_create_creds

def create_pipeline(**kwargs) -> Pipeline:
    return pipeline(
        [
            node(
                func=gcp_create_creds,
                inputs="parameters",
                outputs=None,
                name="gcp_create_creds",
            ),
        ],
        namespace="gcp_creds_create",
        inputs=None,
        outputs=None,
    )
