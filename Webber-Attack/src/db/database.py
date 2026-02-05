"""
Database connection and utilities
"""

import os
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

load_dotenv()


class Database:
    """MySQL database wrapper"""
    
    def __init__(self):
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", 3306))
        self.user = os.getenv("DB_USER")
        self.password = os.getenv("DB_PASSWORD")
        self.database = os.getenv("DB_NAME")
        self.connection = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database
            )
            return self.connection
        except Error as e:
            raise Exception(f"Database connection failed: {e}")
    
    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
    
    def execute(self, query, params=None):
        """Execute a query and return results"""
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(query, params or ())
        return cursor
    
    def fetch_all(self, query, params=None):
        """Execute query and fetch all results"""
        cursor = self.execute(query, params)
        results = cursor.fetchall()
        cursor.close()
        return results
    
    def fetch_one(self, query, params=None):
        """Execute query and fetch one result"""
        cursor = self.execute(query, params)
        result = cursor.fetchone()
        cursor.close()
        return result
    
    def insert(self, query, params=None):
        """Execute insert and return last insert id"""
        cursor = self.execute(query, params)
        self.connection.commit()
        last_id = cursor.lastrowid
        cursor.close()
        return last_id
    
    def update(self, query, params=None):
        """Execute update query"""
        cursor = self.execute(query, params)
        self.connection.commit()
        affected = cursor.rowcount
        cursor.close()
        return affected


# Quick test
if __name__ == "__main__":
    db = Database()
    try:
        db.connect()
        print("✓ Database connected successfully")
        
        # Test query
        tables = db.fetch_all("SHOW TABLES")
        print(f"✓ Found {len(tables)} tables")
        
        db.close()
        print("✓ Database closed")
    except Exception as e:
        print(f"✗ Error: {e}")