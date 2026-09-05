import React, { useEffect, useState } from "react";
import { UserCog, Users } from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { badgeClass } from "../utils/helpers.js";

export function UsersTab() {
  const [users, setUsers] = useState([]);
  const [msg, setMsg] = useState("");
  const [form, setForm] = useState({
    username: "",
    email: "",
    phone: "",
    password: "",
    company: "v-Guard",
    role: "Viewer",
  });
  const [editUser, setEditUser] = useState(null);

  async function load() {
    try {
      setUsers(await api("/api/users"));
    } catch (err) {
      setMsg(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function create() {
    try {
      const r = await api("/api/users", { method: "POST", body: form });
      setMsg(r.message);
      setForm({ ...form, username: "", email: "", phone: "", password: "" });
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  function startEdit(user) {
    setEditUser({
      username: user.username,
      display_name: user.display_name || user.username || "",
      email: user.email || "",
      phone: user.phone || "",
      company: user.company || "v-Guard",
      role: user.role || "Viewer",
      job_title: user.job_title || "",
      department: user.department || "",
      new_password: "",
    });
    setMsg("");
  }

  async function saveEdit() {
    if (!editUser?.username) return;
    try {
      const payload = { ...editUser };
      if (!payload.new_password) delete payload.new_password;
      const r = await api(`/api/users/${encodeURIComponent(editUser.username)}`, {
        method: "PATCH",
        body: payload,
      });
      setMsg(r.message);
      setEditUser(null);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function action(username, type) {
    try {
      const path =
        type === "delete"
          ? `/api/users/${encodeURIComponent(username)}`
          : `/api/users/${encodeURIComponent(username)}/${type}`;
      const r = await api(path, { method: type === "delete" ? "DELETE" : "POST" });
      setMsg(r.message);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  return (
    <section className="page-grid">
      <Panel title="Create User" icon={UserCog}>
        <Message text={msg} />
        <div className="form-grid">
          <input
            placeholder="Username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
          <input
            placeholder="Email (required for password reset)"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
          <input
            placeholder="Phone"
            value={form.phone}
            onChange={(e) => setForm({ ...form, phone: e.target.value })}
          />
          <input
            placeholder="Strong Password"
            type="password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
          <input
            placeholder="Company"
            value={form.company}
            onChange={(e) => setForm({ ...form, company: e.target.value })}
          />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option>Admin</option>
            <option>Analyst</option>
            <option>Viewer</option>
          </select>
          <button className="primary-btn" onClick={create}>
            Create User
          </button>
        </div>
      </Panel>

      {editUser && (
        <Panel title="Edit User" icon={UserCog}>
          <div className="form-grid">
            <input value={editUser.username} disabled placeholder="Username" />
            <input
              placeholder="Display Name"
              value={editUser.display_name}
              onChange={(e) => setEditUser({ ...editUser, display_name: e.target.value })}
            />
            <input
              placeholder="Email"
              value={editUser.email}
              onChange={(e) => setEditUser({ ...editUser, email: e.target.value })}
            />
            <input
              placeholder="Phone"
              value={editUser.phone}
              onChange={(e) => setEditUser({ ...editUser, phone: e.target.value })}
            />
            <input
              placeholder="Company"
              value={editUser.company}
              onChange={(e) => setEditUser({ ...editUser, company: e.target.value })}
            />
            <select value={editUser.role} onChange={(e) => setEditUser({ ...editUser, role: e.target.value })}>
              <option>Admin</option>
              <option>Analyst</option>
              <option>Viewer</option>
            </select>
            <input
              placeholder="Job Title"
              value={editUser.job_title}
              onChange={(e) => setEditUser({ ...editUser, job_title: e.target.value })}
            />
            <input
              placeholder="Department"
              value={editUser.department}
              onChange={(e) => setEditUser({ ...editUser, department: e.target.value })}
            />
            <input
              type="password"
              placeholder="New password (optional)"
              value={editUser.new_password}
              onChange={(e) => setEditUser({ ...editUser, new_password: e.target.value })}
            />
            <p className="muted small">Leave blank to keep password</p>
            <div className="actions">
              <button className="primary-btn" onClick={saveEdit}>
                Save User
              </button>
              <button className="ghost-btn" onClick={() => setEditUser(null)}>
                Cancel Edit
              </button>
            </div>
          </div>
        </Panel>
      )}

      <Panel title="Users" icon={Users} className="full">
        <div className="table-wrap users-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Last Login</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.username}>
                  <td>{u.username}</td>
                  <td>{u.email || "-"}</td>
                  <td>{u.phone || "-"}</td>
                  <td>
                    <span className="badge">{u.role}</span>
                  </td>
                  <td>
                    <span className={badgeClass(u.status)}>{u.status}</span>
                  </td>
                  <td>{u.created_at}</td>
                  <td>{u.last_login_at || "-"}</td>
                  <td className="actions">
                    <button onClick={() => startEdit(u)}>Edit Contact</button>
                    <button onClick={() => action(u.username, "disable")}>Disable</button>
                    <button onClick={() => action(u.username, "enable")}>Enable</button>
                    <button className="danger-btn" onClick={() => action(u.username, "delete")}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </section>
  );
}
