from security import install_security
from pathlib import Path
from fastapi.responses import FileResponse
import logging
import os
from datetime import date
from typing import Annotated, Literal

import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field, field_validator

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing from your .env file.")

logger = logging.getLogger(__name__)

app = FastAPI(
    title="GPS 223 RB II — School Management",
    description="Student admission and records API",
    version="0.1.0",
)

install_security(app)


def get_connection():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
    )


# Return a simple message without exposing database credentials or SQL.
@app.exception_handler(psycopg.OperationalError)
def database_connection_error(
    request: Request,
    exc: psycopg.OperationalError,
):
    logger.error("Database connection unavailable.")
    return JSONResponse(
        status_code=503,
        content={
            "detail": "Database unavailable. Please try again shortly."
        },
    )


class StudentCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    admission_number: str = Field(min_length=1, max_length=50)
    full_name: str = Field(min_length=1, max_length=150)
    father_guardian_name: str = Field(min_length=1, max_length=150)

    date_of_birth: date | None = None
    gender: Literal["male", "female", "other"] | None = None
    guardian_phone: str | None = Field(default=None, max_length=30)
    address: str | None = Field(default=None, max_length=2000)
    admission_date: date = Field(default_factory=date.today)

    @field_validator("date_of_birth", "admission_date")
    @classmethod
    def reject_future_dates(cls, value):
        if value is not None and value > date.today():
            raise ValueError("The date cannot be in the future.")
        return value


@app.get("/", response_class=FileResponse)
def home():
    html_path = Path(__file__).resolve().parent / "index.html"
    return FileResponse(html_path)


@app.get("/classes")
def list_classes():
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, name, sort_order
            FROM classes
            ORDER BY sort_order
            """
        ).fetchall()


@app.post("/students", status_code=201)
def add_student(student: StudentCreate):
    try:
        with get_connection() as conn:
            saved_student = conn.execute(
                """
                INSERT INTO students (
                    admission_number,
                    full_name,
                    father_guardian_name,
                    date_of_birth,
                    gender,
                    guardian_phone,
                    address,
                    admission_date
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                RETURNING *
                """,
                (
                    student.admission_number,
                    student.full_name,
                    student.father_guardian_name,
                    student.date_of_birth,
                    student.gender,
                    student.guardian_phone,
                    student.address,
                    student.admission_date,
                ),
            ).fetchone()

        return saved_student

    except psycopg.errors.UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="This admission number already exists.",
        ) from None


@app.get("/students")
def list_students(
    search: Annotated[
        str | None,
        Query(min_length=1, max_length=150),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    with get_connection() as conn:
        if search:
            return conn.execute(
                """
                SELECT *
                FROM students
                WHERE full_name ILIKE %s
                   OR admission_number ILIKE %s
                ORDER BY id DESC
                LIMIT %s OFFSET %s
                """,
                (
                    f"%{search}%",
                    f"%{search}%",
                    limit,
                    offset,
                ),
            ).fetchall()

        return conn.execute(
            """
            SELECT *
            FROM students
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        ).fetchall()


@app.get("/students/{student_id}")
def get_student(student_id: int):
    with get_connection() as conn:
        student = conn.execute(
            """
            SELECT *
            FROM students
            WHERE id = %s
            """,
            (student_id,),
        ).fetchone()

    if student is None:
        raise HTTPException(
            status_code=404,
            detail="Student not found.",
        )

    return student

class SessionCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    name: str = Field(min_length=1, max_length=30)
    start_date: date
    end_date: date


class EnrollmentCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    student_id: int = Field(gt=0)
    session_id: int = Field(gt=0)
    class_id: int = Field(gt=0)
    section: str | None = Field(default=None, max_length=30)
    roll_number: str | None = Field(default=None, max_length=30)

@app.post("/sessions", status_code=201)
def create_session(session: SessionCreate):
    if session.end_date <= session.start_date:
        raise HTTPException(
            status_code=422,
            detail="End date must be after start date.",
        )

    try:
        with get_connection() as conn:
            saved_session = conn.execute(
                """
                INSERT INTO academic_sessions (
                    name, start_date, end_date
                )
                VALUES (%s, %s, %s)
                RETURNING *
                """,
                (
                    session.name,
                    session.start_date,
                    session.end_date,
                ),
            ).fetchone()

        return saved_session

    except psycopg.errors.UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="A session with this name already exists.",
        ) from None


@app.get("/sessions")
def list_sessions():
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT *
            FROM academic_sessions
            ORDER BY start_date DESC
            """
        ).fetchall()


@app.post("/enrollments", status_code=201)
def enroll_student(enrollment: EnrollmentCreate):
    try:
        with get_connection() as conn:
            # Lock the student record while checking their status.
            student = conn.execute(
                """
                SELECT id, status
                FROM students
                WHERE id = %s
                FOR UPDATE
                """,
                (enrollment.student_id,),
            ).fetchone()

            if student is None:
                raise HTTPException(
                    status_code=404,
                    detail="Student not found.",
                )

            if student["status"] != "active":
                raise HTTPException(
                    status_code=409,
                    detail="Only active students can be enrolled.",
                )

            saved_enrollment = conn.execute(
                """
                INSERT INTO enrollments (
                    student_id,
                    session_id,
                    class_id,
                    section,
                    roll_number
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    enrollment.student_id,
                    enrollment.session_id,
                    enrollment.class_id,
                    enrollment.section,
                    enrollment.roll_number,
                ),
            ).fetchone()

        return saved_enrollment

    except psycopg.errors.UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail=(
                "This student already has an enrollment "
                "in the selected session."
            ),
        ) from None

    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(
            status_code=422,
            detail="The selected session or class does not exist.",
        ) from None


@app.get("/enrollments")
def list_enrollments(
    session_id: Annotated[int, Query(gt=0)],
    class_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    query = """
        SELECT
            e.id AS enrollment_id,
            s.id AS student_id,
            s.admission_number,
            s.full_name,
            s.father_guardian_name,
            s.status AS student_status,
            a.id AS session_id,
            a.name AS academic_session,
            c.id AS class_id,
            c.name AS class_name,
            e.section,
            e.roll_number
        FROM enrollments e
        JOIN students s ON s.id = e.student_id
        JOIN academic_sessions a ON a.id = e.session_id
        JOIN classes c ON c.id = e.class_id
        WHERE e.session_id = %s
    """

    parameters = [session_id]

    if class_id is not None:
        query += " AND e.class_id = %s"
        parameters.append(class_id)

    query += """
        ORDER BY c.sort_order, s.full_name, s.id
        LIMIT %s OFFSET %s
    """
    parameters.extend([limit, offset])

    with get_connection() as conn:
        return conn.execute(query, parameters).fetchall()
    
