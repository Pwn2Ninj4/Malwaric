import sqlite3
import os, sys
from datetime import datetime

from Malwaric.modules import get_paths as path
from Malwaric.modules import colors

db_directory = path.database_path()

def create_db():
    connection = sqlite3.connect(db_directory + "analysis.db")
    cursor = connection.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hash TEXT UNIQUE NOT NULL,
            analysis_datetime TEXT NOT NULL,
            status TEXT NOT NULL,
            virustotal_engine_detect INTEGER NOT NULL,
            notes TEXT
        )
        """)
        
    connection.commit()
    connection.close()
        
def insert_db(name, bin_hash, status, engines, notes):
    
    connection = sqlite3.connect(db_directory + "analysis.db")
    cursor = connection.cursor()
    
    cursor.execute("""
        INSERT INTO file_analysis (name, hash, analysis_datetime, status, virustotal_engine_detect, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (name, bin_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status, engines, notes))
    
    connection.commit()
    connection.close()
    
def view_content():
    
    connection = sqlite3.connect(db_directory + "analysis.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT * FROM file_analysis")
    file_data = cursor.fetchall()
    
    return file_data
    
    connection.close()