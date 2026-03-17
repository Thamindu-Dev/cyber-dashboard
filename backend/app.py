"""
AI-Powered DDoS Detection System - FastAPI Backend
Optimized for HuggingFace Spaces deployment
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
from pathlib import Path
import logging
from datetime import datetime
import io

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize rate limiter
# Rate limits: 10 requests per minute for upload endpoint, 60/minute for others
limiter = Limiter(key_func=get_remote_address)
logger.info("✅ Rate limiter initialized")

# Initialize FastAPI app
app = FastAPI(
    title="AI-Powered DDoS Detection API",
    description="Production-ready DDoS detection using XGBoost models trained on CICDDoS2019",
    version="1.0.0"
)

# Add rate limit exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware for HF Spaces
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for models
classifier = None
regressor = None
label_encoder = None
traffic_scaler = None

# Feature order must match the trained models exactly (81 features)
FEATURE_COLUMNS = [
    'Source Port', 'Destination Port', 'Protocol', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Inbound'
]

# Non-numeric columns to automatically drop
NON_NUMERIC_COLUMNS = [
    'Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'SimillarHTTP'
]


def load_models():
    """Load all pre-trained models and artifacts."""
    global classifier, regressor, label_encoder, traffic_scaler

    try:
        base_path = Path(__file__).parent

        # Detect CUDA availability for HF Spaces
        try:
            import torch
            use_cuda = torch.cuda.is_available()
            logger.info(f"CUDA available: {use_cuda}")
        except:
            use_cuda = False
            logger.info("CUDA detection failed, using CPU")

        # Load XGBoost Classifier
        classifier_path = base_path / "Classification model" / "xgboost_ddos_classifier.json"
        if not classifier_path.exists():
            raise FileNotFoundError(f"Classifier not found at {classifier_path}")

        classifier = xgb.XGBClassifier()
        classifier.load_model(str(classifier_path))
        logger.info("✅ Classifier loaded")

        # Load Label Encoder
        encoder_path = base_path / "Classification model" / "label_encoder.joblib"
        label_encoder = joblib.load(encoder_path)
        logger.info("✅ Label encoder loaded")

        # Load XGBoost Regressor
        regressor_path = base_path / "Regression Model" / "xgboost_severity_regressor.json"
        if not regressor_path.exists():
            raise FileNotFoundError(f"Regressor not found at {regressor_path}")

        regressor = xgb.XGBRegressor()
        regressor.load_model(str(regressor_path))
        logger.info("✅ Regressor loaded")

        # Load Traffic Scaler
        scaler_path = base_path / "Regression Model" / "traffic_scaler.joblib"
        traffic_scaler = joblib.load(scaler_path)
        logger.info("✅ Traffic scaler loaded")

        return True

    except Exception as e:
        logger.error(f"❌ Error loading models: {str(e)}")
        raise


def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Preprocess input DataFrame for model inference."""
    # Strip column names
    df.columns = df.columns.str.strip()

    # Replace infinity with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows with NaN
    initial_rows = len(df)
    df.dropna(inplace=True)

    if initial_rows - len(df) > 0:
        logger.warning(f"Dropped {initial_rows - len(df)} rows with NaN values")

    # Drop non-numeric columns
    existing_non_numeric = [col for col in NON_NUMERIC_COLUMNS if col in df.columns]
    if existing_non_numeric:
        df = df.drop(columns=existing_non_numeric)

    # Check for missing features
    missing_features = set(FEATURE_COLUMNS) - set(df.columns)
    if missing_features:
        raise ValueError(f"Missing required features: {missing_features}")

    # Select features in exact order
    df_processed = df[FEATURE_COLUMNS].copy()

    # Convert to numeric
    for col in df_processed.columns:
        df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce')

    df_processed.dropna(inplace=True)

    return df_processed


def run_inference(df: pd.DataFrame):
    """Run inference using both models."""
    # Classification prediction (works on raw data)
    attack_predictions = classifier.predict(df)

    # Severity prediction requires scaled data
    # Scale the features before prediction
    try:
        df_scaled = traffic_scaler.transform(df)
        severity_scores = regressor.predict(df_scaled)

        # Ensure severity scores are in valid range [0, 100]
        severity_scores = np.clip(severity_scores, 0, 100)
    except Exception as e:
        logger.warning(f"Scaling failed, using raw data: {e}")
        # Fallback: predict on raw data and clip
        severity_scores = np.clip(regressor.predict(df), 0, 100)

    return attack_predictions, severity_scores


def generate_report(df, attack_predictions, severity_scores):
    """Generate comprehensive analysis report."""
    attack_labels = label_encoder.inverse_transform(attack_predictions)

    # Attack distribution
    unique, counts = np.unique(attack_labels, return_counts=True)
    attack_distribution = dict(zip(unique.tolist(), counts.tolist()))

    # Severity statistics
    avg_severity = float(np.mean(severity_scores))
    max_severity = float(np.max(severity_scores))

    # Critical alerts (>70%)
    critical_mask = severity_scores > 70
    critical_count = int(np.sum(critical_mask))

    # Sample critical alerts
    critical_alerts = []
    if critical_count > 0:
        critical_indices = np.where(critical_mask)[0][:100]
        for idx in critical_indices:
            alert = {
                "flow_index": int(idx),
                "attack_type": str(attack_labels[idx]),
                "severity_score": round(float(severity_scores[idx]), 2),
                "source_port": int(df.iloc[idx]['Source Port']),
                "destination_port": int(df.iloc[idx]['Destination Port']),
                "protocol": int(df.iloc[idx]['Protocol'])
            }
            critical_alerts.append(alert)

    # Severity distribution
    severity_dist = {
        "low_risk (0-30%)": int(np.sum((severity_scores >= 0) & (severity_scores <= 30))),
        "medium_risk (31-60%)": int(np.sum((severity_scores > 30) & (severity_scores <= 60))),
        "high_risk (61-85%)": int(np.sum((severity_scores > 60) & (severity_scores <= 85))),
        "critical (86-100%)": int(np.sum(severity_scores > 85))
    }

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_flows_analyzed": int(len(attack_labels)),
            "unique_attack_types_detected": int(len(unique)),
            "average_severity_score": round(avg_severity, 2),
            "max_severity_score": round(max_severity, 2),
            "critical_alerts_count": critical_count,
            "benign_flow_count": int(attack_distribution.get('BENIGN', 0))
        },
        "attack_distribution": attack_distribution,
        "severity_distribution": severity_dist,
        "critical_alerts_sample": critical_alerts
    }


@app.on_event("startup")
async def startup_event():
    """Load models on startup."""
    logger.info("🚀 Starting DDoS Detection API...")
    try:
        load_models()
        logger.info("✅ API ready!")
    except Exception as e:
        logger.error(f"❌ Startup failed: {str(e)}")
        raise


@app.get("/")
@limiter.limit("60/minute")
async def root(request: Request):
    """API information."""
    return {
        "message": "AI-Powered DDoS Detection System",
        "version": "1.0.0",
        "status": "operational",
        "rate_limits": {
            "upload_csv": "10 requests per minute",
            "health_check": "60 requests per minute",
            "root": "60 requests per minute"
        },
        "endpoints": {
            "/upload-csv": "POST - Upload CSV for analysis (10/minute, max 100MB)",
            "/health": "GET - Health check (60/minute)",
            "/": "GET - API information (60/minute)"
        },
        "limits": {
            "max_file_size": "100MB",
            "rate_limit_upload": "10 requests per minute",
            "rate_limit_others": "60 requests per minute"
        }
    }


@app.get("/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """Health check endpoint."""
    return {
        "status": "healthy" if all([classifier, regressor, label_encoder, traffic_scaler]) else "unhealthy",
        "models_loaded": {
            "classifier": classifier is not None,
            "regressor": regressor is not None,
            "label_encoder": label_encoder is not None,
            "traffic_scaler": traffic_scaler is not None
        }
    }


@app.post("/upload-csv")
@limiter.limit("10/minute")
async def upload_csv(request: Request, file: UploadFile = File(...)):
    """
    Upload CSV for DDoS analysis.

    Accepts CSV files with network traffic data and returns
    comprehensive attack detection and severity analysis.

    Limits:
    - Max file size: 100MB
    - Rate limit: 10 requests per minute
    """
    if not file.filename.lower().endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files supported")

    start_time = datetime.now()

    try:
        # Read file content
        contents = await file.read()

        # File size validation (100MB limit)
        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
        if len(contents) > MAX_FILE_SIZE:
            logger.warning(f"File too large: {len(contents) / (1024 * 1024):.1f}MB")
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is 100MB. Your file is {len(contents) / (1024 * 1024):.1f}MB. Please split your file into smaller parts."
            )

        if len(contents) == 0:
            logger.warning("Empty file uploaded")
            raise HTTPException(status_code=400, detail="Empty file uploaded")

        # Read CSV with better error handling
        try:
            df = pd.read_csv(io.BytesIO(contents), low_memory=False)
        except pd.errors.EmptyDataError:
            logger.error("CSV parsing failed: Empty data")
            raise HTTPException(status_code=400, detail="CSV file is empty or corrupted")
        except pd.errors.ParserError:
            logger.error("CSV parsing failed: Invalid format")
            raise HTTPException(status_code=400, detail="Invalid CSV format. Please check your file structure")
        except Exception as e:
            logger.error(f"CSV parsing failed: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Failed to read CSV file: {str(e)}")

        if len(df) == 0:
            logger.warning("Empty DataFrame after CSV read")
            raise HTTPException(status_code=400, detail="CSV file contains no data")

        logger.info(f"Processing file: {file.filename} ({len(df)} rows)")

        # Preprocess
        try:
            df_processed = preprocess_dataframe(df)
        except ValueError as e:
            logger.warning(f"Preprocessing failed: {str(e)}")
            raise HTTPException(status_code=400, detail=str(e))

        if len(df_processed) == 0:
            logger.warning("No valid data after preprocessing")
            raise HTTPException(
                status_code=400,
                detail="No valid data after preprocessing. Please ensure your CSV has all required columns and numeric values."
            )

        logger.info(f"Preprocessed: {len(df_processed)} valid rows")

        # Run inference
        try:
            attack_predictions, severity_scores = run_inference(df_processed)
        except Exception as e:
            logger.error(f"Model inference failed: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Model inference failed. Please try again or contact support."
            )

        # Generate report
        try:
            report = generate_report(df_processed, attack_predictions, severity_scores)
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Failed to generate analysis report"
            )

        report["processing_time_seconds"] = round((datetime.now() - start_time).total_seconds(), 2)
        report["input_filename"] = file.filename

        logger.info(f"Analysis completed successfully in {report['processing_time_seconds']}s")
        return JSONResponse(content=report)

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except MemoryError:
        logger.error("Memory error during processing")
        raise HTTPException(
            status_code=507,
            detail="Insufficient memory to process this file. Try a smaller file."
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred. Please try again or contact support if the problem persists."
        )
