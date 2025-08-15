import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect, jsonify
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# User authentication helpers
def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user


def get_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?',
                        (post_id,)).fetchone()
    conn.close()
    if post is None:
        abort(404)
    return post

# Get comments for a post
def get_comments(post_id):
    conn = get_db_connection()
    comments = conn.execute('SELECT c.*, u.username FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created ASC', (post_id,)).fetchall()
    conn.close()
    return [dict(c) for c in comments]

# Fetch a single comment by id
def get_comment_by_id(comment_id):
    conn = get_db_connection()
    comment = conn.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    conn.close()
    if comment is None:
        abort(404)
    return comment


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'

# Create optional tables if missing (e.g., reports)
def ensure_optional_tables():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_user_id INTEGER NOT NULL,
            target_type TEXT NOT NULL CHECK(target_type IN ('post','comment')),
            target_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reporter_user_id) REFERENCES users (id)
        )
        """
    )
    # Ensure users.intro column exists for older databases
    try:
        has_intro = conn.execute("SELECT 1 FROM pragma_table_info('users') WHERE name='intro'").fetchone()
        if not has_intro:
            conn.execute("ALTER TABLE users ADD COLUMN intro TEXT DEFAULT ''")
    except Exception:
        pass
    conn.commit()
    conn.close()

ensure_optional_tables()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password'])
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts ORDER BY created DESC').fetchall()
    conn.close()
    return render_template('index.html', posts=[dict(p) for p in posts], user=current_user if current_user.is_authenticated else None)


@app.route('/<int:post_id>')
def post(post_id):
    post = get_post(post_id)
    comments = get_comments(post_id)
    # Determine favorite state for the current user
    is_favorite = False
    if current_user.is_authenticated:
        conn = get_db_connection()
        fav = conn.execute('SELECT 1 FROM favorites WHERE user_id = ? AND post_id = ?',
                           (current_user.id, post_id)).fetchone()
        conn.close()
        is_favorite = fav is not None
    return render_template('post.html', post=post, comments=comments, is_favorite=is_favorite,
                           user=current_user if current_user.is_authenticated else None)


# -----------------------------
# Public JSON API for posts
# -----------------------------

def _serialize_post_row(row):
    return {
        'id': row['id'],
        'title': row['title'],
        'content': row['content'],
        'created': row['created'],
        'author': {
            'id': row['user_id'],
            'username': row['username'] if 'username' in row.keys() else None,
        }
    }


@app.route('/api/posts', methods=['GET'])
def api_list_posts():
    try:
        limit = request.args.get('limit', default=50, type=int)
        offset = request.args.get('offset', default=0, type=int)
        limit = 50 if limit is None else max(1, min(limit, 200))
        offset = 0 if offset is None else max(0, offset)

        conn = get_db_connection()
        rows = conn.execute(
            'SELECT p.id, p.title, p.content, p.created, p.user_id, u.username '
            'FROM posts p LEFT JOIN users u ON u.id = p.user_id '
            'ORDER BY p.created DESC LIMIT ? OFFSET ?',
            (limit, offset)
        ).fetchall()
        conn.close()
        data = [_serialize_post_row(r) for r in rows]
        return jsonify({'posts': data, 'limit': limit, 'offset': offset})
    except Exception as e:
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/api/posts/<int:post_id>', methods=['GET'])
def api_get_post(post_id):
    include = request.args.get('include', '')
    include_comments = 'comments' in {part.strip().lower() for part in include.split(',') if part}
    conn = get_db_connection()
    row = conn.execute(
        'SELECT p.id, p.title, p.content, p.created, p.user_id, u.username '
        'FROM posts p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = ?',
        (post_id,)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Post not found'}), 404
    post_dict = _serialize_post_row(row)
    if include_comments:
        comments = conn.execute(
            'SELECT c.id, c.post_id, c.user_id, c.content, c.created, u.username '
            'FROM comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.post_id = ? '
            'ORDER BY c.created ASC',
            (post_id,)
        ).fetchall()
        post_dict['comments'] = [
            {
                'id': c['id'],
                'content': c['content'],
                'created': c['created'],
                'user': {'id': c['user_id'], 'username': c['username']},
            }
            for c in comments
        ]
    conn.close()
    return jsonify(post_dict)


# -----------------------------
# OpenAPI (Swagger) documentation
# -----------------------------

def build_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "CodeBlog API",
            "version": "1.0.0",
            "description": "Read-only API to list posts and fetch a single post with optional comments."
        },
        "servers": [
            {"url": "/"}
        ],
        "paths": {
            "/api/posts": {
                "get": {
                    "summary": "List posts",
                    "description": "Returns a paginated list of posts ordered by newest first.",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
                            "description": "Max items to return (1-200)."
                        },
                        {
                            "name": "offset",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 0, "default": 0},
                            "description": "Number of items to skip."
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "A list of posts",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "posts": {"type": "array", "items": {"$ref": "#/components/schemas/Post"}},
                                            "limit": {"type": "integer"},
                                            "offset": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        },
                        "500": {"description": "Internal Server Error"}
                    }
                }
            },
            "/api/posts/{post_id}": {
                "get": {
                    "summary": "Get a single post",
                    "parameters": [
                        {
                            "name": "post_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        },
                        {
                            "name": "include",
                            "in": "query",
                            "schema": {"type": "string", "example": "comments"},
                            "description": "Optional comma-separated inclusions. Use 'comments' to embed comments."
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "The post",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/PostWithOptionalComments"}
                                }
                            }
                        },
                        "404": {"description": "Post not found"}
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Author": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "nullable": True},
                        "username": {"type": "string", "nullable": True}
                    }
                },
                "Comment": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "content": {"type": "string"},
                        "created": {"type": "string"},
                        "user": {"$ref": "#/components/schemas/Author"}
                    }
                },
                "Post": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "title": {"type": "string"},
                        "content": {"type": "string"},
                        "created": {"type": "string"},
                        "author": {"$ref": "#/components/schemas/Author"}
                    }
                },
                "PostWithOptionalComments": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Post"},
                        {
                            "type": "object",
                            "properties": {
                                "comments": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Comment"}
                                }
                            }
                        }
                    ]
                }
            }
        }
    }


@app.route('/api/openapi.json')
def openapi_json():
    return jsonify(build_openapi_spec())


@app.route('/api/docs')
def api_docs():
    # Renders Swagger UI pointing at our OpenAPI JSON
    return render_template('api_docs.html', spec_url=url_for('openapi_json'))

@app.route('/<int:post_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(post_id):
    # Toggle favorite for the logged-in user and the given post
    conn = get_db_connection()
    existing = conn.execute('SELECT 1 FROM favorites WHERE user_id = ? AND post_id = ?',
                            (current_user.id, post_id)).fetchone()
    if existing:
        conn.execute('DELETE FROM favorites WHERE user_id = ? AND post_id = ?',
                     (current_user.id, post_id))
        flash('Removed from favorites.', 'info')
    else:
        conn.execute('INSERT INTO favorites (user_id, post_id) VALUES (?, ?)',
                     (current_user.id, post_id))
        flash('Added to favorites', 'info')
    conn.commit()
    conn.close()
    return redirect(url_for('post', post_id=post_id))
@app.route('/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form['content']
    # BUG 2: 500 error on special character in comment
    import re
    if not content:
        flash('Comment cannot be empty!', 'error')
    elif re.search(r'[^a-zA-Z0-9\s]', content):
        raise Exception('Special characters not allowed!')
    else:
        conn = get_db_connection()
        conn.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                     (post_id, current_user.id, content))
        conn.commit()
        conn.close()
        flash('Comment added!', 'info')
    return redirect(url_for('post', post_id=post_id))


# Report a post
@app.route('/report/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def report_post(post_id):
    post = get_post(post_id)
    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash('Reason is required to submit a report.', 'error')
        elif (post['user_id'] is not None) and int(post['user_id']) == int(current_user.id):
            flash('You cannot report your own post.', 'error')
        else:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO reports (reporter_user_id, target_type, target_id, reason) VALUES (?, ?, ?, ?)',
                (current_user.id, 'post', post_id, reason)
            )
            conn.commit()
            conn.close()
            flash('Report submitted. Thank you.', 'info')
            return redirect(url_for('post', post_id=post_id))
    return render_template('report.html', user=current_user if current_user.is_authenticated else None,
                           target_type='post', post=dict(post))


# Report a comment
@app.route('/report/comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def report_comment(comment_id):
    comment = get_comment_by_id(comment_id)
    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash('Reason is required to submit a report.', 'error')
        elif (comment['user_id'] is not None) and int(comment['user_id']) == int(current_user.id):
            flash('You cannot report your own comment.', 'error')
        else:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO reports (reporter_user_id, target_type, target_id, reason) VALUES (?, ?, ?, ?)',
                (current_user.id, 'comment', comment_id, reason)
            )
            conn.commit()
            conn.close()
            flash('Report submitted. Thank you.', 'info')
            return redirect(url_for('post', post_id=comment['post_id']))
    return render_template('report.html', user=current_user if current_user.is_authenticated else None,
                           target_type='comment', comment=dict(comment))


@app.route('/create', methods=('GET', 'POST'))
def create():
    if not current_user.is_authenticated:
        flash('You must be logged in to create a post.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title:
            flash('Title is required!', 'error')
        else:
            conn = get_db_connection()
            # Associate post with the logged-in user
            conn.execute('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                         (title, content, current_user.id))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('create.html', user=current_user)
@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # BUG 1: Allow empty password
        if not username:
            flash('Username is required!', 'error')
        elif User.get_by_username(username):
            flash('Username already exists! Please choose a different username.', 'error')
        else:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                         (username, generate_password_hash(password)))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'info')
            return redirect(url_for('login'))
    return render_template('register.html', user=current_user if current_user.is_authenticated else None)


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'info')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html', user=current_user if current_user.is_authenticated else None)


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('index'))


# Change password feature
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    message = None
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        user = User.get(current_user.id)
        if not check_password_hash(user.password, current_password):
            error = 'Current password is incorrect.'
        elif new_password != confirm_password:
            error = 'New passwords do not match.'
        elif not new_password:
            error = 'New password cannot be empty.'
        else:
            conn = get_db_connection()
            conn.execute('UPDATE users SET password = ? WHERE id = ?',
                         (generate_password_hash(new_password), current_user.id))
            conn.commit()
            conn.close()
            message = 'Password changed successfully.'
    return render_template('change_password.html', user=current_user, error=error, message=message)


# User profile page showing the logged-in user's posts and comments
@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    # User's own posts
    subject_id = current_user.id
    profile_row = get_user_by_id(subject_id)
    user_posts = conn.execute(
        'SELECT id, title, created FROM posts WHERE user_id = ? ORDER BY created DESC',
        (subject_id,)
    ).fetchall()
    # User's comments with related post titles
    user_comments = conn.execute(
        'SELECT c.post_id, c.content, c.created, p.title AS post_title '
        'FROM comments c JOIN posts p ON p.id = c.post_id '
        'WHERE c.user_id = ? ORDER BY c.created DESC',
    (subject_id,)
    ).fetchall()
    # Optional favorites if used
    favorites = conn.execute(
        'SELECT p.id, p.title FROM favorites f JOIN posts p ON p.id = f.post_id '
        'WHERE f.user_id = ? ORDER BY p.created DESC',
        (subject_id,)
    ).fetchall()
    conn.close()

    return render_template(
        'user_profile.html',
    user=current_user,
        profile_user={
            'id': current_user.id,
            'username': current_user.username,
            'intro': (profile_row['intro'] if (profile_row is not None and ('intro' in profile_row.keys())) else '')
        },
        user_posts=[dict(p) for p in user_posts],
        user_comments=[dict(c) for c in user_comments],
        favorites=[dict(f) for f in favorites],
    )


# Public profile page for any username
@app.route('/user/<username>')
def public_profile(username):
    target = get_user_by_username(username)
    if not target:
        abort(404)
    subject_id = target['id']
    conn = get_db_connection()
    user_posts = conn.execute(
        'SELECT id, title, created FROM posts WHERE user_id = ? ORDER BY created DESC',
        (subject_id,)
    ).fetchall()
    user_comments = conn.execute(
        'SELECT c.post_id, c.content, c.created, p.title AS post_title '
        'FROM comments c JOIN posts p ON p.id = c.post_id '
        'WHERE c.user_id = ? ORDER BY c.created DESC',
        (subject_id,)
    ).fetchall()
    favorites = conn.execute(
        'SELECT p.id, p.title FROM favorites f JOIN posts p ON p.id = f.post_id '
        'WHERE f.user_id = ? ORDER BY p.created DESC',
        (subject_id,)
    ).fetchall()
    conn.close()

    return render_template(
        'user_profile.html',
        user=current_user if current_user.is_authenticated else None,
    profile_user={'id': target['id'], 'username': target['username'], 'intro': (target['intro'] if ('intro' in target.keys()) else '')},
        user_posts=[dict(p) for p in user_posts],
        user_comments=[dict(c) for c in user_comments],
        favorites=[dict(f) for f in favorites],
    )


# Edit current user's intro
@app.route('/profile/intro', methods=['POST'])
@login_required
def update_intro():
    intro = request.form.get('intro', '').strip()
    if len(intro) > 2000:
        flash('Introduction is too long (max 2000 characters).', 'error')
        return redirect(url_for('profile'))
    conn = get_db_connection()
    conn.execute('UPDATE users SET intro = ? WHERE id = ?', (intro, current_user.id))
    conn.commit()
    conn.close()
    flash('Introduction updated.', 'info')
    return redirect(url_for('profile'))


@app.route('/<int:id>/edit', methods=('GET', 'POST'))
def edit(id):
    if not current_user.is_authenticated:
        flash('You must be logged in to edit posts.', 'error')
        return redirect(url_for('login'))
    post = get_post(id)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title:
            flash('Title is required!', 'error')
        else:
            conn = get_db_connection()
            conn.execute('UPDATE posts SET title = ?, content = ?'
                         ' WHERE id = ?',
                         (title, content, id))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('edit.html', post=post, user=current_user)


@app.route('/<int:id>/delete', methods=('POST',))
def delete(id):
    if not current_user.is_authenticated:
        flash('You must be logged in to delete posts.', 'error')
        return redirect(url_for('login'))
    post = get_post(id)
    conn = get_db_connection()
    conn.execute('DELETE FROM posts WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('"{}" was successfully deleted!'.format(post['title']), 'info')
    return redirect(url_for('index'))
