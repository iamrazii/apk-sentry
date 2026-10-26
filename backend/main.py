# main.py
import os
import shutil
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from starlette.middleware.base import BaseHTTPMiddleware

from engine.aggregator import HybridAggregator
from engine.heuristics import HeuristicEngine
from engine.ml_classifier import MLClassifier
from schemas import RiskAssessmentResponse

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(name)s] - %(message)s",
)
logger = logging.getLogger("AndroidMalwareAPI")

MODEL_PATH = "Scripts/artifacts/android_malware_random_forest.joblib"
YARA_PATH = "rules/threat_rules.yar"

ml_classifier = None
heuristic_engine = None
hybrid_aggregator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ml_classifier, heuristic_engine, hybrid_aggregator

    logger.info("Initializing detection engines...")
    if os.path.exists(MODEL_PATH) and os.path.exists(YARA_PATH):
        try:
            ml_classifier = MLClassifier(model_path=MODEL_PATH, default_threshold=0.35)
            heuristic_engine = HeuristicEngine(yara_rules_path=YARA_PATH)
            hybrid_aggregator = HybridAggregator(
                heuristic_weight=0.6,
                ml_weight=0.4,
                suspicious_threshold=0.35,
                critical_threshold=0.65,
            )
            logger.info("Detection Engines Initialized Successfully.")
        except Exception as e:
            logger.exception(f"Failed to initialize detection engines: {str(e)}")
    else:
        logger.warning(f"Missing MODEL_PATH ({MODEL_PATH}) or YARA_PATH ({YARA_PATH})")

    yield

    logger.info("Shutting down API service...")
    ml_classifier = None
    heuristic_engine = None
    hybrid_aggregator = None


app = FastAPI(
    title="Android Malware Detection API",
    description="Hybrid detection engine API.",
    version="2.2.0",
    lifespan=lifespan,
)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"

        logger.info(f"[{request_id}] Incoming request: {request.method} {request.url.path} from {client_ip}")

        try:
            response = await call_next(request)
            process_time = (time.time() - start_time) * 1000
            logger.info(
                f"[{request_id}] Completed {request.method} {request.url.path} "
                f"| Status: {response.status_code} | Time: {process_time:.2f}ms"
            )
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as e:
            process_time = (time.time() - start_time) * 1000
            logger.exception(
                f"[{request_id}] Request failed: {request.method} {request.url.path} "
                f"| Error: {str(e)} | Time: {process_time:.2f}ms"
            )
            raise


app.add_middleware(RequestLoggingMiddleware)


@app.post("/analyze-apk", response_model=RiskAssessmentResponse)
async def analyze_apk(file: UploadFile = File(...)):
    if not ml_classifier or not heuristic_engine or not hybrid_aggregator:
        logger.error("Analysis rejected: Detection engines not loaded.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection engines are not loaded.",
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext != ".apk":
        logger.warning(f"Analysis rejected for file '{file.filename}': Invalid extension '{ext}'")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload an .apk file.",
        )

    logger.info(f"Processing uploaded file: '{file.filename}'")

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp_file:
        shutil.copyfileobj(file.file, temp_file)
        temp_path = temp_file.name

    try:
        start_eval_time = time.time()

        ml_results = ml_classifier.predict(temp_path)
        heuristic_results = heuristic_engine.analyze(temp_path)

        final_report = hybrid_aggregator.aggregate(heuristic_results, ml_results)

        eval_duration = (time.time() - start_eval_time) * 1000
        logger.info(
            f"Analysis complete for '{file.filename}' in {eval_duration:.2f}ms. "
            f"Verdict: {final_report['verdict']} | Total Score: {final_report['threat_scores']['total_score']:.4f}"
        )

        return RiskAssessmentResponse(
            filename=file.filename,
            is_malware=final_report["is_malware"],
            verdict=final_report["verdict"],
            risk_tier=final_report["risk_tier"],
            confidence=ml_results.get("confidence", 0.0),
            static_score=final_report["threat_scores"]["static_score"],
            ml_score=final_report["threat_scores"]["ml_score"],
            total_score=final_report["threat_scores"]["total_score"],
            thresholds_used=final_report["thresholds"],
            audit_trail=final_report["audit_trail"],
            triggered_rules=final_report["detailed_rule_triggers"],
        )

    except Exception as e:
        logger.exception(f"Error occurred during APK analysis for '{file.filename}': {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing APK file: {str(e)}",
        )
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
            logger.debug(f"Cleaned up temporary file: {temp_path}")