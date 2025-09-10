const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const fs = require("fs");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Hardcoded username and password
const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync("123", 10); // Hash your password

// Multer Storage for File Uploads
const storage = multer.memoryStorage();

const upload = multer({ storage });

// User Login (No MySQL)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USERNAME) {
    return res.status(200).json({ message: "Invalid username" });
  }

  const isMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!isMatch) {
    return res.status(200).json({ message: "Invalid password" });
  }

  res.json({ token: "123", role: "admin", message: "Login successful" });
});

// Middleware to Protect Routes
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Fix token format
  if (!token) return res.status(403).json({ message: "Access Denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid Token" });
    req.user = decoded;
    next();
  });
};

// Protected Dashboard Route
app.get("/api/dashboard", (req, res) => {
  res.json({ message: "Welcome to Admin Dashboard!" });
});

// MySQL Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost", // for cPanel, MySQL host is usually 'localhost'
  user: process.env.DB_USER || "root", // the user you created
  password: process.env.DB_PASSWORD || "", // the password you set in cPanel
  database: process.env.DB_NAME || "bachelor_admission", // your database name
});

db.connect((err) => {
  if (err) {
    console.error("Database Connection Failed:", err);
  } else {
    console.log("Connected to MySQL Database");
  }
});
app.use("/uploads", express.static("uploads"));

// Route: Get All Students

// Existing GET: Get All Students
app.get("/api/students", (req, res) => {
  db.query("SELECT * FROM students", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// New GET: Get a Single Student by ID
app.get("/api/students/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM students WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0)
      return res.status(404).json({ error: "Student not found" });
    res.json(results[0]);
  });
});

// Existing POST: Add a New Admission
app.post(
  "/api/admission",
  upload.fields([
    { name: "photo" },
    { name: "id_card" },
    { name: "transcript" },
  ]),
  (req, res) => {
    const {
      first_name,
      last_name,
      father_name,
      birthdate,
      birth_place,
      gender,
      phone_number,
      email,
      province,
      address,
      relative_phone_1,
      relative_phone_2,
      field_of_study_1,
      field_of_study_2,
    } = req.body;

    const photo_filename = req.files["photo"]
      ? req.files["photo"][0].filename
      : null;
    const id_card_filename = req.files["id_card"]
      ? req.files["id_card"][0].filename
      : null;
    const transcript_filename = req.files["transcript"]
      ? req.files["transcript"][0].filename
      : null;

    const sql = `INSERT INTO students (
    first_name, last_name, father_name, birthdate, birth_place, gender, 
    phone_number, email, province, address, relative_phone_1, relative_phone_2, 
    field_of_study_1, field_of_study_2, photo_filename, id_card_filename, transcript_filename
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const values = [
      first_name,
      last_name,
      father_name,
      birthdate,
      birth_place,
      gender,
      phone_number,
      email,
      province,
      address,
      relative_phone_1,
      relative_phone_2,
      field_of_study_1,
      field_of_study_2,
      photo_filename,
      id_card_filename,
      transcript_filename,
    ];

    db.query(sql, values, (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({
        message: "Student registered successfully!",
        id: result.insertId,
      });
    });
  }
);

// New DELETE: Delete a Student by ID and remove associated files
app.delete("/api/students/:id", (req, res) => {
  const studentId = req.params.id;

  // Get student file paths before deletion
  db.query(
    "SELECT photo_filename, id_card_filename, transcript_filename FROM students WHERE id = ?",
    [studentId],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (results.length === 0)
        return res.status(404).json({ error: "Student not found" });

      const { photo_filename, id_card_filename, transcript_filename } =
        results[0];

      // Delete student record from DB
      db.query("DELETE FROM students WHERE id = ?", [studentId], (err) => {
        if (err)
          return res.status(500).json({ error: "Failed to delete student" });

        // Remove files
        [photo_filename, id_card_filename, transcript_filename].forEach(
          (file) => {
            if (file) {
              fs.unlink(path.join(__dirname, "uploads", file), (err) => {
                if (err) console.error(`Error deleting file ${file}:`, err);
              });
            }
          }
        );

        res.json({ message: "Student deleted successfully" });
      });
    }
  );
});

app.get("/api/news", (req, res) => {
  db.query("SELECT * FROM news ORDER BY created_at DESC", (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    // Convert image BLOB to base64 for each record
    const newsWithImages = results.map((row) => {
      let imageBase64 = null;
      if (row.image_url) {
        imageBase64 = Buffer.from(row.image_url).toString("base64");
      }

      return {
        id: row.id,
        title: row.title,
        content: row.content,
        created_at: row.created_at,
        // Send image as base64 string
        image: imageBase64 ? `data:image/jpeg;base64,${imageBase64}` : null,
      };
    });

    res.json(newsWithImages);
  });
});
app.post("/api/news", upload.single("image"), (req, res) => {
  const { title, content } = req.body;
  const image = req.file ? req.file.buffer : null; // store binary

  const query = "INSERT INTO news (title, content, image_url) VALUES (?, ?, ?)";
  db.query(query, [title, content, image], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ id: results.insertId, title, content });
  });
});

// Endpoint to update a news article
app.get("/api/news/image/:id", (req, res) => {
  const { id } = req.params;
  const query = "SELECT image_url FROM news WHERE id = ?";

  db.query(query, [id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: "Image not found" });
    }

    const image = results[0].image_url;
    res.setHeader("Content-Type", "image/jpeg"); // adjust for PNG if needed
    res.send(image);
  });
});

// Endpoint to delete a news article
app.delete("/api/news/:id", (req, res) => {
  const { id } = req.params;

  // Delete the news entry directly from the database
  db.query("DELETE FROM news WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ error: "Article not found" });
    }

    res.json({ message: "Article deleted successfully" });
  });
});

// Endpoint to add a new policy
app.post("/api/policies", upload.single("pdf_file"), async (req, res) => {
  const { title, description, date, status } = req.body;

  // Check for missing required fields
  if (!title || !date || !status) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    // Get the file buffer if uploaded
    const pdfBuffer = req.file ? req.file.buffer : null;

    // Insert into the policies table (make sure pdf_file column is BLOB)
    const query =
      "INSERT INTO academic_policies (title, description, date, status, pdf_file) VALUES (?, ?, ?, ?, ?)";
    db.query(
      query,
      [title, description, date, status, pdfBuffer],
      (err, results) => {
        if (err) {
          console.error("Error inserting policy:", err);
          return res.status(500).json({ message: "Internal server error" });
        }
        res.json({
          id: results.insertId,
          title,
          description,
          date,
          status,
          pdf_file: pdfBuffer ? true : false, // just to indicate it exists
        });
      }
    );
  } catch (error) {
    console.error("Error saving policy:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Endpoint to get all policies
// Get all policies
// Get list of policies (without PDF data)
app.get("/api/policies", (req, res) => {
  const query =
    "SELECT id, title, description, date, status FROM academic_policies ORDER BY date DESC";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching policies:", err);
      return res.status(500).json({ message: "Failed to fetch policies" });
    }
    // Return only metadata, PDF will be fetched separately
    res.json(results);
  });
});

// Serve PDF by policy ID
app.get("/api/policies/pdf/:id", (req, res) => {
  const { id } = req.params;
  const query = "SELECT pdf_file FROM academic_policies WHERE id = ?";

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Error fetching PDF:", err);
      return res.status(500).json({ message: "Failed to fetch PDF" });
    }

    if (results.length === 0 || !results[0].pdf_file) {
      return res.status(404).json({ message: "PDF not found" });
    }

    const pdfData = results[0].pdf_file;

    // Set headers for PDF file download/view
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename=policy_${id}.pdf`);
    res.send(pdfData); // Send PDF blob directly
  });
});

// Delete a policy by ID
app.delete("/api/policies/:id", (req, res) => {
  const { id } = req.params;

  // Delete the policy record from the database
  const deleteQuery = "DELETE FROM academic_policies WHERE id = ?";
  db.query(deleteQuery, [id], (err, results) => {
    if (err) {
      console.error("Error deleting policy:", err);
      return res.status(500).json({ message: "Failed to delete policy" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Policy not found" });
    }

    res.json({ message: "Policy deleted successfully" });
  });
});

// Get all jobs (for counting jobs)
app.get("/api/jobs", (req, res) => {
  const sql = "SELECT * FROM job";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching jobs:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

// Add a new job
app.post("/api/jobs", (req, res) => {
  const { job_title, job_code, announcement_date, closing_date } = req.body;

  if (!job_title || !job_code) {
    return res.status(400).json({ error: "Job title and code are required" });
  }

  const sql = `INSERT INTO job (job_title, job_code, announcement_date, closing_date) VALUES (?, ?, ?, ?)`;
  db.query(
    sql,
    [job_title, job_code, announcement_date, closing_date],
    (err, result) => {
      if (err) {
        console.error("Error inserting job:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json({ message: "Job inserted successfully", id: result.insertId });
    }
  );
});
// Delete a job by ID
// Delete a job by ID
app.delete("/api/jobs/:id", (req, res) => {
  const jobId = req.params.id;
  const sql = "DELETE FROM job WHERE id = ?";

  db.query(sql, [jobId], (err, result) => {
    if (err) {
      console.error("Error deleting job:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Job not found" });
    }
    res.json({ message: "Job deleted successfully" });
  });
});

// POST: Submit research paper
app.post("/api/submit", upload.single("pdf_file"), (req, res) => {
  const {
    author_first_name,
    author_last_name,
    author_phone,
    author_email,
    university_name,
    department_name,
    paper_title,
    province,
  } = req.body;

  const pdf_file = req.file ? req.file.path : null;

  const sql = `INSERT INTO research_paper_submissions 
    (author_first_name, author_last_name, author_phone, author_email, university_name, department_name, paper_title, province, pdf_file)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  db.query(
    sql,
    [
      author_first_name,
      author_last_name,
      author_phone,
      author_email,
      university_name,
      department_name,
      paper_title,
      province,
      pdf_file,
    ],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Database error");
      }
      res.status(201).send("Submission saved successfully");
    }
  );
});

// GET: All submissions
app.get("/api/submissions", (req, res) => {
  db.query("SELECT * FROM research_paper_submissions", (err, results) => {
    if (err) return res.status(500).send("Database error");
    res.json(results);
  });
});

// DELETE: Delete submission by ID
app.delete("/api/submissions/:id", (req, res) => {
  const id = req.params.id;

  // Get PDF path to delete file
  db.query(
    "SELECT pdf_file FROM research_paper_submissions WHERE id = ?",
    [id],
    (err, result) => {
      if (err || result.length === 0)
        return res.status(404).send("Submission not found");

      const pdfPath = result[0].pdf_file;
      if (pdfPath && fs.existsSync(pdfPath)) {
        fs.unlinkSync(pdfPath);
      }

      db.query(
        "DELETE FROM research_paper_submissions WHERE id = ?",
        [id],
        (err) => {
          if (err) return res.status(500).send("Error deleting submission");
          res.send("Submission deleted");
        }
      );
    }
  );
});

app.use("/uploads", express.static("uploads")); // Serve uploaded files

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
