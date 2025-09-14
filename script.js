/**
 * Staff Complaint Management System - JavaScript
 * Main application logic and functionality
 */

// Global Variables
let complaints = [];
let complaintIdCounter = 1;
let currentUser = {};
let currentComplaintId = null;
let currentFilter = "all";

// Initialize the application
document.addEventListener("DOMContentLoaded", function () {
  console.log("Staff Complaint Management System loaded");
  initializeApp();
});

/**
 * Initialize the application
 */
function initializeApp() {
  loadData();
  showSection("login");
  addDemoData();
  setupProfileImageUpload();
}

/**
 * Load data from localStorage
 */
function loadData() {
  try {
    complaints = JSON.parse(localStorage.getItem("complaints") || "[]");
    complaintIdCounter = parseInt(
      localStorage.getItem("complaintIdCounter") || "1"
    );
    currentUser = JSON.parse(localStorage.getItem("currentUser") || "{}");

    console.log("Data loaded successfully");
    console.log("Complaints:", complaints.length);
    console.log("Current User:", currentUser.name || "None");
  } catch (error) {
    console.error("Error loading data:", error);
    complaints = [];
    complaintIdCounter = 1;
    currentUser = {};
  }
}

/**
 * Save data to localStorage
 */
function saveData() {
  try {
    localStorage.setItem("complaints", JSON.stringify(complaints));
    localStorage.setItem("complaintIdCounter", complaintIdCounter.toString());
    localStorage.setItem("currentUser", JSON.stringify(currentUser));
    console.log("Data saved successfully");
  } catch (error) {
    console.error("Error saving data:", error);
    showNotification("Error saving data", "error");
  }
}

/**
 * Show specific section and hide others
 */
function showSection(sectionId) {
  console.log("Showing section:", sectionId);

  // Hide all sections
  const sections = document.querySelectorAll("section");
  sections.forEach((section) => {
    section.classList.add("hidden");
  });

  // Show the requested section
  const targetSection = document.getElementById(sectionId + "-section");
  if (targetSection) {
    targetSection.classList.remove("hidden");
  } else {
    console.error("Section not found:", sectionId);
    return;
  }

  // Show/hide navbar based on section
  const navbar = document.getElementById("main-navbar");
  const showNavbarSections = [
    "dashboard",
    "file-complaint",
    "complaint-list",
    "complaint-details",
    "profile",
  ];

  if (showNavbarSections.includes(sectionId)) {
    navbar.classList.remove("hidden");
  } else {
    navbar.classList.add("hidden");
  }

  // Update content based on section
  if (sectionId === "dashboard") {
    updateDashboard();
  } else if (sectionId === "complaint-list") {
    displayComplaints();
  } else if (sectionId === "admin-complaints") {
    displayAdminComplaints();
  }
}

/**
 * Handle staff login
 */
function handleLogin(event) {
  event.preventDefault();
  console.log("Attempting login...");

  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value.trim();

  // Basic validation
  if (!username || !password) {
    showNotification("Please enter both username and password", "error");
    return;
  }

  // Simple authentication (in real app, this would be server-side)
  currentUser = {
    username: username,
    name: username.includes("@") ? username.split("@")[0] : username,
    email: username.includes("@") ? username : username + "@qcexpress.com",
    type: "staff",
  };

  saveData();

  // Update UI
  const userNameElement = document.getElementById("user-name");
  if (userNameElement) {
    userNameElement.textContent = currentUser.name;
  }

  // Clear form
  document.getElementById("login-username").value = "";
  document.getElementById("login-password").value = "";

  showSection("dashboard");
  showNotification("Login successful! Welcome " + currentUser.name, "success");
  console.log("User logged in:", currentUser.name);
}

/**
 * Handle staff registration
 */
function handleSignup(event) {
  event.preventDefault();
  console.log("Attempting signup...");

  const name = document.getElementById("signup-name").value.trim();
  const email = document.getElementById("signup-email").value.trim();
  const username = document.getElementById("signup-username").value.trim();
  const password = document.getElementById("signup-password").value.trim();
  const confirmPassword = document
    .getElementById("confirm-password")
    .value.trim();

  // Validation
  if (!name || !email || !username || !password || !confirmPassword) {
    showNotification("Please fill in all fields", "error");
    return;
  }

  if (password !== confirmPassword) {
    showNotification("Passwords do not match", "error");
    return;
  }

  if (password.length < 6) {
    showNotification("Password must be at least 6 characters", "error");
    return;
  }

  // Clear form
  document.getElementById("signup-name").value = "";
  document.getElementById("signup-email").value = "";
  document.getElementById("signup-username").value = "";
  document.getElementById("signup-password").value = "";
  document.getElementById("confirm-password").value = "";

  showNotification(
    "Account created successfully! Please login with your credentials.",
    "success"
  );
  showSection("login");

  // Pre-fill login form
  document.getElementById("login-username").value = username;
  console.log("User registered:", name);
}

/**
 * Handle admin login
 */
function handleAdminLogin(event) {
  event.preventDefault();
  console.log("Attempting admin login...");

  const email = document.getElementById("admin-email").value.trim();
  const password = document.getElementById("admin-password").value.trim();

  if (!email || !password) {
    showNotification("Please enter admin credentials", "error");
    return;
  }

  // Simple admin authentication
  currentUser = {
    email: email,
    name: "Administrator",
    type: "admin",
  };

  saveData();

  // Clear form
  document.getElementById("admin-email").value = "";
  document.getElementById("admin-password").value = "";

  showSection("admin-dashboard");
  showNotification("Admin login successful!", "success");
  console.log("Admin logged in");
}

/**
 * Handle complaint submission
 */
function handleComplaintSubmission(event) {
  event.preventDefault();
  console.log("Submitting complaint...");

  const title = document.getElementById("complaint-title").value.trim();
  const category = document.getElementById("complaint-category").value;
  const description = document
    .getElementById("complaint-description")
    .value.trim();
  const attachmentInput = document.getElementById("complaint-attachment");

  // Validation
  if (!title || !category || !description) {
    showNotification("Please fill in all required fields", "error");
    return;
  }

  if (description.length < 10) {
    showNotification("Description must be at least 10 characters", "error");
    return;
  }

  // Create complaint object
  const complaint = {
    id: complaintIdCounter++,
    title: title,
    category: category,
    description: description,
    status: "pending",
    dateSubmitted: new Date().toISOString().split("T")[0],
    user: currentUser.email || currentUser.username,
    comments: [],
    attachment: attachmentInput.files[0] ? attachmentInput.files[0].name : null,
  };

  complaints.push(complaint);
  saveData();

  // Clear form
  document.getElementById("complaint-title").value = "";
  document.getElementById("complaint-category").value = "";
  document.getElementById("complaint-description").value = "";
  document.getElementById("complaint-attachment").value = "";

  showNotification(
    "Complaint submitted successfully! ID: #" +
      complaint.id.toString().padStart(3, "0"),
    "success"
  );
  showSection("dashboard");
  console.log("Complaint submitted:", complaint.id);
}

/**
 * Handle profile update
 */
function handleProfileUpdate(event) {
  event.preventDefault();
  console.log("Updating profile...");

  const name = document.getElementById("profile-name").value.trim();
  const email = document.getElementById("profile-email").value.trim();
  const phone = document.getElementById("profile-phone").value.trim();
  const position = document.getElementById("profile-position").value.trim();

  if (!name || !email) {
    showNotification("Name and email are required", "error");
    return;
  }

  // Update current user (in real app, this would update server)
  currentUser.name = name;
  currentUser.email = email;
  currentUser.phone = phone;
  currentUser.position = position;

  saveData();

  // Update dashboard name
  const userNameElement = document.getElementById("user-name");
  if (userNameElement) {
    userNameElement.textContent = currentUser.name;
  }

  showNotification("Profile updated successfully!", "success");
  console.log("Profile updated for:", currentUser.name);
}

/**
 * Update dashboard with current data
 */
function updateDashboard() {
  console.log("Updating dashboard...");

  const userComplaints = complaints.filter(
    (c) => c.user === (currentUser.email || currentUser.username)
  );

  const pendingCount = userComplaints.filter(
    (c) => c.status === "pending"
  ).length;
  const progressCount = userComplaints.filter(
    (c) => c.status === "in-progress"
  ).length;
  const resolvedCount = userComplaints.filter(
    (c) => c.status === "resolved"
  ).length;

  // Update status cards
  const pendingElement = document.getElementById("pending-count");
  const progressElement = document.getElementById("progress-count");
  const resolvedElement = document.getElementById("resolved-count");
  const totalElement = document.getElementById("total-complaints");

  if (pendingElement) pendingElement.textContent = pendingCount;
  if (progressElement) progressElement.textContent = progressCount;
  if (resolvedElement) resolvedElement.textContent = resolvedCount;
  if (totalElement) totalElement.textContent = userComplaints.length;

  // Display recent complaints
  displayRecentComplaints(userComplaints.slice(-5).reverse());

  console.log(
    "Dashboard updated - Total:",
    userComplaints.length,
    "Pending:",
    pendingCount
  );
}

/**
 * Display recent complaints on dashboard
 */
function displayRecentComplaints(recentComplaints) {
  const container = document.getElementById("recent-complaints");
  if (!container) return;

  if (recentComplaints.length === 0) {
    container.innerHTML = `
            <div class="text-center" style="padding: 2rem; color: #6b7280;">
                <p>No complaints filed yet.</p>
                <button class="btn" onclick="showSection('file-complaint')" style="margin-top: 1rem;">
                    File Your First Complaint
                </button>
            </div>
        `;
    return;
  }

  container.innerHTML = recentComplaints
    .map(
      (complaint) => `
        <div class="complaint-item" onclick="viewComplaintDetails(${
          complaint.id
        })" style="margin-bottom: 1rem; cursor: pointer;">
            <div class="complaint-header">
                <div>
                    <h4 class="complaint-title">${complaint.title}</h4>
                    <div class="complaint-meta">
                        <span>ID: #${complaint.id
                          .toString()
                          .padStart(3, "0")}</span>
                        <span>Category: ${complaint.category}</span>
                        <span>Date: ${complaint.dateSubmitted}</span>
                    </div>
                </div>
                <span class="badge ${
                  complaint.status
                }">${complaint.status.replace("-", " ")}</span>
            </div>
            <p>${
              complaint.description.length > 100
                ? complaint.description.substring(0, 100) + "..."
                : complaint.description
            }</p>
        </div>
    `
    )
    .join("");
}

/**
 * Display complaints list with optional filtering
 */
function displayComplaints(statusFilter = "all") {
  console.log("Displaying complaints with filter:", statusFilter);

  const userComplaints = complaints.filter(
    (c) => c.user === (currentUser.email || currentUser.username)
  );
  let filteredComplaints = userComplaints;

  if (statusFilter !== "all") {
    filteredComplaints = userComplaints.filter(
      (c) => c.status === statusFilter
    );
  }

  const container = document.getElementById("complaint-list");
  if (!container) return;

  if (filteredComplaints.length === 0) {
    container.innerHTML = `
            <li style="text-align: center; padding: 3rem; color: #6b7280; list-style: none;">
                <h4>No complaints found</h4>
                <p>Try adjusting your filter or file a new complaint.</p>
                <button class="btn" onclick="showSection('file-complaint')" style="margin-top: 1rem;">
                    File New Complaint
                </button>
            </li>
        `;
    return;
  }

  container.innerHTML = filteredComplaints
    .map(
      (complaint) => `
        <li class="complaint-item" onclick="viewComplaintDetails(${
          complaint.id
        })">
            <div class="complaint-header">
                <div>
                    <h4 class="complaint-title">${complaint.title}</h4>
                    <div class="complaint-meta">
                        <span>ID: #${complaint.id
                          .toString()
                          .padStart(3, "0")}</span>
                        <span>Category: ${complaint.category}</span>
                        <span>Date: ${complaint.dateSubmitted}</span>
                        ${
                          complaint.attachment
                            ? `<span>📎 ${complaint.attachment}</span>`
                            : ""
                        }
                    </div>
                </div>
                <span class="badge ${
                  complaint.status
                }">${complaint.status.replace("-", " ")}</span>
            </div>
            <p>${
              complaint.description.length > 150
                ? complaint.description.substring(0, 150) + "..."
                : complaint.description
            }</p>
        </li>
    `
    )
    .join("");

  console.log("Displayed", filteredComplaints.length, "complaints");
}

/**
 * Filter complaints by status
 */
function filterComplaints(status) {
  console.log("Filtering complaints by:", status);
  currentFilter = status;

  // Update active filter button
  document.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.classList.remove("active");
  });
  event.target.classList.add("active");

  displayComplaints(status);
}

/**
 * View detailed complaint information
 */
function viewComplaintDetails(complaintId) {
  console.log("Viewing complaint details:", complaintId);

  currentComplaintId = complaintId;
  const complaint = complaints.find((c) => c.id === complaintId);

  if (!complaint) {
    showNotification("Complaint not found", "error");
    return;
  }

  const complaintInfo = document.getElementById("complaint-info");
  if (!complaintInfo) return;

  complaintInfo.innerHTML = `
        <div style="background: #f8fafc; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; border-left: 5px solid var(--primary-blue);">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <h3 style="margin: 0 0 1rem 0; color: var(--primary-blue);">${
                      complaint.title
                    }</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                        <div><strong>ID:</strong> #${complaint.id
                          .toString()
                          .padStart(3, "0")}</div>
                        <div><strong>Category:</strong> ${
                          complaint.category
                        }</div>
                        <div><strong>Date:</strong> ${
                          complaint.dateSubmitted
                        }</div>
                        <div><strong>User:</strong> ${complaint.user}</div>
                    </div>
                </div>
                <span class="badge ${
                  complaint.status
                }" style="font-size: 14px; padding: 0.75rem 1rem;">${complaint.status.replace(
    "-",
    " "
  )}</span>
            </div>
            <div style="margin-top: 1.5rem;">
                <strong style="color: var(--primary-blue);">Description:</strong>
                <p style="margin-top: 0.5rem; line-height: 1.6; background: white; padding: 1rem; border-radius: 8px;">${
                  complaint.description
                }</p>
            </div>
            ${
              complaint.attachment
                ? `
                <div style="margin-top: 1rem;">
                    <strong style="color: var(--primary-blue);">Attachment:</strong>
                    <span style="margin-left: 0.5rem; padding: 0.25rem 0.75rem; background: #e2e8f0; border-radius: 20px; font-size: 14px;">📎 ${complaint.attachment}</span>
                </div>
            `
                : ""
            }
        </div>
    `;

  displayComments(complaint.comments);
  showSection("complaint-details");
}

/**
 * Display comments for a complaint
 */
function displayComments(comments) {
  const container = document.getElementById("comments-list");
  if (!container) return;

  if (comments.length === 0) {
    container.innerHTML =
      '<p style="color: #6b7280; text-align: center; padding: 2rem;">No updates or comments yet.</p>';
    return;
  }

  container.innerHTML = comments
    .map(
      (comment) => `
        <div class="comment-item" style="background: #f1f5f9; padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem; border-left: 4px solid var(--primary-blue);">
            <div class="comment-author" style="font-weight: 600; color: var(--primary-blue); margin-bottom: 0.5rem;">${comment.author}</div>
            <div class="comment-date" style="font-size: 12px; color: #6b7280; margin-bottom: 1rem;">${comment.date}</div>
            <p style="line-height: 1.6; margin: 0;">${comment.text}</p>
        </div>
    `
    )
    .join("");
}

/**
 * Add a new comment to the current complaint
 */
function addComment() {
  const commentText = document.getElementById("new-comment").value.trim();

  if (!commentText) {
    showNotification("Please enter a comment", "error");
    return;
  }

  if (commentText.length < 5) {
    showNotification("Comment must be at least 5 characters", "error");
    return;
  }

  const complaint = complaints.find((c) => c.id === currentComplaintId);
  if (!complaint) {
    showNotification("Complaint not found", "error");
    return;
  }

  const comment = {
    author: currentUser.name || currentUser.username,
    text: commentText,
    date: new Date().toLocaleDateString(),
    time: new Date().toLocaleTimeString(),
  };

  complaint.comments.push(comment);
  saveData();

  document.getElementById("new-comment").value = "";
  displayComments(complaint.comments);
  showNotification("Comment added successfully!", "success");
  console.log("Comment added to complaint:", currentComplaintId);
}

/**
 * Display admin complaints (all complaints from all users)
 */
function displayAdminComplaints(statusFilter = "all") {
  console.log("Displaying admin complaints with filter:", statusFilter);

  let filteredComplaints = complaints;

  if (statusFilter !== "all") {
    filteredComplaints = complaints.filter((c) => c.status === statusFilter);
  }

  const container = document.getElementById("admin-complaint-list");
  if (!container) return;

  if (filteredComplaints.length === 0) {
    container.innerHTML = `
            <div style="text-align: center; padding: 3rem; color: #6b7280;">
                <h4>No complaints found</h4>
                <p>No complaints match the selected filter.</p>
            </div>
        `;
    return;
  }

  container.innerHTML = filteredComplaints
    .map(
      (complaint) => `
        <div class="complaint-item">
            <div class="complaint-header">
                <div>
                    <h4 class="complaint-title">${complaint.title}</h4>
                    <div class="complaint-meta">
                        <span>ID: #${complaint.id
                          .toString()
                          .padStart(3, "0")}</span>
                        <span>User: ${complaint.user}</span>
                        <span>Category: ${complaint.category}</span>
                        <span>Date: ${complaint.dateSubmitted}</span>
                    </div>
                </div>
                <span class="badge ${
                  complaint.status
                }">${complaint.status.replace("-", " ")}</span>
            </div>
            <p>${
              complaint.description.length > 120
                ? complaint.description.substring(0, 120) + "..."
                : complaint.description
            }</p>
            <div style="margin-top: 1.5rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                <button class="btn btn-success" onclick="updateComplaintStatus(${
                  complaint.id
                }, 'resolved')" style="margin-right: 0.5rem;">
                    Mark as Resolved
                </button>
                <button class="btn btn-secondary" onclick="updateComplaintStatus(${
                  complaint.id
                }, 'in-progress')" style="margin-right: 0.5rem;">
                    Set In Progress
                </button>
                <button class="btn" onclick="viewComplaintDetails(${
                  complaint.id
                })" style="background: var(--lilac);">
                    View Details
                </button>
            </div>
        </div>
    `
    )
    .join("");

  console.log("Displayed", filteredComplaints.length, "admin complaints");
}

/**
 * Filter admin complaints by status
 */
function filterAdminComplaints(status) {
  console.log("Filtering admin complaints by:", status);
  currentFilter = status;

  // Update active filter button
  document.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.classList.remove("active");
  });
  event.target.classList.add("active");

  displayAdminComplaints(status);
}

/**
 * Update complaint status (admin function)
 */
function updateComplaintStatus(complaintId, newStatus) {
  console.log("Updating complaint status:", complaintId, "to", newStatus);

  const complaint = complaints.find((c) => c.id === complaintId);
  if (!complaint) {
    showNotification("Complaint not found", "error");
    return;
  }

  const oldStatus = complaint.status;
  complaint.status = newStatus;

  // Add a system comment about the status change
  const statusComment = {
    author: "System Admin",
    text: `Status changed from "${oldStatus}" to "${newStatus}"`,
    date: new Date().toLocaleDateString(),
    time: new Date().toLocaleTimeString(),
  };

  complaint.comments.push(statusComment);
  saveData();

  showNotification(
    `Complaint #${complaintId
      .toString()
      .padStart(3, "0")} marked as ${newStatus}`,
    "success"
  );
  displayAdminComplaints(currentFilter);
}

/**
 * Logout function
 */
function logout() {
  console.log("Logging out user:", currentUser.name || "Unknown");

  // Clear current user data
  currentUser = {};
  localStorage.removeItem("currentUser");

  // Reset form fields
  document.querySelectorAll("input").forEach((input) => {
    if (input.type !== "file") {
      input.value = "";
    }
  });

  document.querySelectorAll("textarea").forEach((textarea) => {
    textarea.value = "";
  });

  document.querySelectorAll("select").forEach((select) => {
    select.selectedIndex = 0;
  });

  showSection("login");
  showNotification("Logged out successfully", "success");
}

/**
 * Show notification to user
 */
function showNotification(message, type = "info") {
  console.log("Notification:", type, "-", message);

  // Remove any existing notifications
  const existingNotifications = document.querySelectorAll(".notification");
  existingNotifications.forEach((notification) => {
    if (notification.parentNode) {
      notification.parentNode.removeChild(notification);
    }
  });

  // Create notification element
  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.textContent = message;

  // Add to page
  document.body.appendChild(notification);

  // Show notification
  setTimeout(() => {
    notification.classList.add("show");
  }, 100);

  // Hide and remove notification after 4 seconds
  setTimeout(() => {
    notification.classList.remove("show");
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }, 4000);
}

/**
 * Setup profile image upload functionality
 */
function setupProfileImageUpload() {
  const profilePicInput = document.getElementById("profile-pic-input");
  const profileImage = document.getElementById("profile-image");

  if (profilePicInput && profileImage) {
    profilePicInput.addEventListener("change", function (event) {
      const file = event.target.files[0];
      if (file) {
        if (file.type.startsWith("image/")) {
          const reader = new FileReader();
          reader.onload = function (e) {
            profileImage.src = e.target.result;
            showNotification("Profile picture updated!", "success");
          };
          reader.readAsDataURL(file);
        } else {
          showNotification("Please select a valid image file", "error");
          profilePicInput.value = "";
        }
      }
    });
  }
}

/**
 * Add demo data for testing purposes
 */
function addDemoData() {
  if (complaints.length === 0) {
    console.log("Adding demo data...");

    const demoComplaints = [
      {
        id: 1,
        title: "Package Delivery Delay",
        category: "Delivery",
        description:
          "My package was supposed to arrive yesterday but it still hasn't been delivered. The tracking shows it's at the local facility since 3 days ago. This is causing inconvenience as I needed the items for an important meeting.",
        status: "pending",
        dateSubmitted: "2024-01-15",
        user: "john.doe@qcexpress.com",
        comments: [
          {
            author: "Customer Service",
            text: "We have received your complaint and are investigating the delay with our delivery partner.",
            date: "2024-01-16",
            time: "10:30 AM",
          },
        ],
        attachment: "tracking_screenshot.png",
      },
      {
        id: 2,
        title: "Website Login Issues",
        category: "Technical",
        description:
          "I've been having trouble logging into the company portal for the past 2 days. It keeps saying my credentials are invalid even though I'm using the correct username and password. I've tried resetting my password but didn't receive the reset email.",
        status: "in-progress",
        dateSubmitted: "2024-01-14",
        user: "jane.smith@qcexpress.com",
        comments: [
          {
            author: "IT Support",
            text: "We are looking into this issue. IT department has been notified and is working on a solution.",
            date: "2024-01-14",
            time: "2:15 PM",
          },
          {
            author: "IT Support",
            text: "The issue has been identified as a server-side authentication problem. We are deploying a fix.",
            date: "2024-01-15",
            time: "9:45 AM",
          },
        ],
      },
      {
        id: 3,
        title: "Air Conditioning Malfunction",
        category: "Maintenance",
        description:
          "The air conditioning unit in the main office has been making loud noises and not cooling properly for the past week. It's affecting productivity as the office gets very hot during the day.",
        status: "resolved",
        dateSubmitted: "2024-01-10",
        user: "mike.wilson@qcexpress.com",
        comments: [
          {
            author: "Maintenance Team",
            text: "Maintenance request logged. We will send a technician to inspect the unit.",
            date: "2024-01-11",
            time: "8:30 AM",
          },
          {
            author: "Maintenance Team",
            text: "AC unit has been repaired and is working normally. The issue was a faulty compressor that has been replaced.",
            date: "2024-01-12",
            time: "3:00 PM",
          },
        ],
      },
      {
        id: 4,
        title: "Poor Customer Service Experience",
        category: "Services",
        description:
          "I had a very poor experience with the customer service team yesterday. The representative was rude and unhelpful when I called about a billing issue. This is not the quality of service I expect from QC Express.",
        status: "pending",
        dateSubmitted: "2024-01-16",
        user: "sarah.jones@qcexpress.com",
        comments: [],
      },
    ];

    complaints = demoComplaints;
    complaintIdCounter = 5;
    saveData();
    console.log("Demo data added successfully");
  }
}

/**
 * Generate random complaint ID for demo purposes
 */
function generateComplaintId() {
  return Math.floor(Math.random() * 1000) + 1;
}

/**
 * Format date for display
 */
function formatDate(date) {
  if (typeof date === "string") {
    return new Date(date).toLocaleDateString();
  }
  return date.toLocaleDateString();
}

/**
 * Validate email format
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Get complaint statistics
 */
function getComplaintStats() {
  const stats = {
    total: complaints.length,
    pending: complaints.filter((c) => c.status === "pending").length,
    inProgress: complaints.filter((c) => c.status === "in-progress").length,
    resolved: complaints.filter((c) => c.status === "resolved").length,
    byCategory: {},
  };

  // Count by category
  complaints.forEach((complaint) => {
    stats.byCategory[complaint.category] =
      (stats.byCategory[complaint.category] || 0) + 1;
  });

  return stats;
}

/**
 * Export complaints data (for future enhancement)
 */
function exportComplaints() {
  const dataStr = JSON.stringify(complaints, null, 2);
  const dataUri =
    "data:application/json;charset=utf-8," + encodeURIComponent(dataStr);

  const exportFileDefaultName =
    "complaints_export_" + new Date().toISOString().split("T")[0] + ".json";

  const linkElement = document.createElement("a");
  linkElement.setAttribute("href", dataUri);
  linkElement.setAttribute("download", exportFileDefaultName);
  linkElement.click();

  showNotification("Complaints data exported successfully", "success");
}

/**
 * Search complaints by keyword
 */
function searchComplaints(keyword) {
  if (!keyword.trim()) {
    return complaints;
  }

  const searchTerm = keyword.toLowerCase();
  return complaints.filter(
    (complaint) =>
      complaint.title.toLowerCase().includes(searchTerm) ||
      complaint.description.toLowerCase().includes(searchTerm) ||
      complaint.category.toLowerCase().includes(searchTerm) ||
      complaint.user.toLowerCase().includes(searchTerm)
  );
}

/**
 * Handle keyboard shortcuts
 */
document.addEventListener("keydown", function (event) {
  // Ctrl/Cmd + K to focus search (if implemented)
  if ((event.ctrlKey || event.metaKey) && event.key === "k") {
    event.preventDefault();
    // Focus search input if it exists
    const searchInput = document.querySelector('input[type="search"]');
    if (searchInput) {
      searchInput.focus();
    }
  }

  // Escape key to close modals or go back
  if (event.key === "Escape") {
    // Handle escape key functionality here
  }
});

/**
 * Handle window resize for responsive design
 */
window.addEventListener("resize", function () {
  // Handle any resize-specific functionality here
  console.log("Window resized:", window.innerWidth, "x", window.innerHeight);
});

/**
 * Handle page visibility change
 */
document.addEventListener("visibilitychange", function () {
  if (document.visibilityState === "visible") {
    // Reload data when page becomes visible again
    loadData();
    if (
      document.getElementById("dashboard-section") &&
      !document.getElementById("dashboard-section").classList.contains("hidden")
    ) {
      updateDashboard();
    }
  }
});

// Error handling for uncaught errors
window.addEventListener("error", function (event) {
  console.error("JavaScript error:", event.error);
  showNotification("An error occurred. Please refresh the page.", "error");
});

// Log when script is fully loaded
console.log("Staff Complaint Management System - Script loaded successfully");
console.log("Version: 1.0.0");
console.log("Ready for user interaction");
