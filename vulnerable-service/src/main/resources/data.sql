-- Seed data for dependent service
INSERT INTO USERS (name, password, email, role) VALUES ('admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@vulnerable.local', 'admin');
INSERT INTO USERS (name, password, email, role) VALUES ('user1', '5f4dcc3b5aa765d61d8327deb882cf99', 'user1@vulnerable.local', 'user');
INSERT INTO USERS (name, password, email, role) VALUES ('test', '098f6bcd4621d373cade4e832627b4f6', 'test@vulnerable.local', 'user');
