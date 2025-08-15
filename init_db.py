import sqlite3
import os
from glob import glob

# Remove db file if it exists
if os.path.exists('database.db'):
    os.remove('database.db')

connection = sqlite3.connect('database.db')


with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

import werkzeug.security

# Add test users
users = [
    ('admin', werkzeug.security.generate_password_hash('admin')),
    ('alice', werkzeug.security.generate_password_hash('alice123')),
    ('bob', werkzeug.security.generate_password_hash('bob456')),
    ('charlie', werkzeug.security.generate_password_hash('charlie789'))
]
for username, password in users:
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))

# Add example intros for users
intros = {
    'admin': 'Site admin. I enjoy building tools and keeping things running smoothly.',
    'alice': 'Python enthusiast and data wrangler. I write about Flask and APIs.',
    'bob': 'Full-stack tinkerer. I like clean code and good coffee.',
    'charlie': 'Backend developer exploring databases and performance.'
}
for username, intro in intros.items():
    cur.execute("UPDATE users SET intro = ? WHERE username = ?", (intro, username))

def load_posts_from_data(data_dir='data'):
    posts = []
    pattern = os.path.join(data_dir, '*.txt')
    for path in sorted(glob(pattern)):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read().strip()
            if not text:
                continue
            lines = text.splitlines()
            # First non-empty line as title
            title = None
            body_lines = []
            for line in lines:
                if title is None and line.strip():
                    title = line.strip()
                    continue
                body_lines.append(line)
            if not title:
                # Fallback to filename as title
                title = os.path.splitext(os.path.basename(path))[0].replace('-', ' ').title()
            content = '\n'.join(body_lines).lstrip('\n')
            posts.append((title, content))
        except Exception as e:
            print(f"Skipping {path}: {e}")
    return posts

# Add programming-related blog posts from data files
for title, content in load_posts_from_data('data'):
    cur.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))

# Add realistic comments from various users
comments = [
    (1, 2, 'Great explanation! Decorators always confused me, but this helped.'),
    (1, 3, 'Can you show an example with arguments?'),
    (1, 4, 'I use decorators for logging in my projects. Very useful!'),
    (2, 1, 'Flask is my favorite Python framework. Thanks for the intro!'),
    (2, 3, 'How does Flask compare to Django?'),
    (3, 2, 'I agree with using meaningful variable names. It makes a big difference.'),
    (3, 4, 'What tools do you recommend for code formatting?'),
    (4, 1, 'Joins can be tricky at first. Thanks for breaking it down.'),
    (4, 2, 'Could you add an example with LEFT JOIN?'),
    (4, 3, 'Nice post! I always forget the difference between INNER and OUTER joins.')
]
for post_id, user_id, content in comments:
    cur.execute("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)", (post_id, user_id, content))

# Add example private messages between users
messages = [
    # sender, recipient, content
    ('alice', 'bob', 'Hey Bob, loved your comment on decorators!'),
    ('bob', 'alice', 'Thanks Alice! Want to pair on a Flask app?'),
    ('charlie', 'alice', 'Great post ideas. Let\'s chat about databases.'),
]
user_ids = {u[0]: idx+1 for idx, u in enumerate(users)}
for sender, recipient, content in messages:
    cur.execute(
        "INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)",
        (user_ids[sender], user_ids[recipient], content)
    )

connection.commit()
connection.close()
