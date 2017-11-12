-- 2017-11-12 Erik
CREATE TABLE ad_users (
  id         BIGSERIAL              NOT NULL,
  first_name CHARACTER VARYING(80),
  last_name  CHARACTER VARYING(80),
  user_name  CHARACTER VARYING(255) NOT NULL,
  password   CHARACTER VARYING(100) NOT NULL,

  CONSTRAINT ad_users_pk PRIMARY KEY (id)
);
