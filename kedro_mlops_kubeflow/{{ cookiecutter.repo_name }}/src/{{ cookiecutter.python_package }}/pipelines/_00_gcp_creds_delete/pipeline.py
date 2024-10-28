from kedro.pipeline import Pipeline, node
from kedro.pipeline.modular_pipeline import pipeline
from .nodes import gcp_delete_creds


def create_pipeline(**kwargs) -> Pipeline:
    return pipeline(
        [
            node(
                func=gcp_delete_creds,
                inputs="parameters",
                outputs=None,
                name="gcp_delete_creds",
            ),
        ],
        namespace="gcp_creds_delete",
        inputs=None,
        outputs=None,
    )
