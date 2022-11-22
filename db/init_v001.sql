DROP TABLE IF EXISTS allowed_values;
DROP TABLE IF EXISTS claims;
DROP TABLE IF EXISTS capabilities;
DROP TABLE IF EXISTS trusted_issuers;

CREATE TABLE trusted_issuers (
    id varchar(255),
    PRIMARY KEY (id)
);

CREATE TABLE capabilities (
    id int AUTO_INCREMENT,
    valid_from varchar(255),
    valid_to varchar(255),
    credentials_type varchar(255),
    trusted_issuer varchar(255),
    PRIMARY KEY (id),
    FOREIGN KEY (trusted_issuer) REFERENCES trusted_issuers (id)
);

CREATE TABLE claims(
    id int AUTO_INCREMENT,
    name varchar(255),
    capability int,
    PRIMARY KEY (id),
    FOREIGN KEY (capability) REFERENCES capabilities (id)
);

CREATE TABLE allowed_values (
    id int AUTO_INCREMENT,
    allowed_value varchar(255), 
    claim int,
    PRIMARY KEY (id),
    FOREIGN KEY (claim) REFERENCES claims (id)
);