package com.viskei.animalcontrol.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Table(name = "roles")
@Getter
@Setter
@ToString
@NoArgsConstructor
public class Role {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  @Enumerated(EnumType.STRING)
  @Column(length = 20, unique = true)
  private ERole name;

  public Role(ERole name) {
    this.name = name;
  }
}